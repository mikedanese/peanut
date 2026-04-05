//! Pure-Rust cBPF (classic BPF) interpreter for seccomp policies.
//!
//! This interpreter executes compiled BPF programs against a seccomp data context
//! in-process, without loading the kernel filter. Used for property-based testing
//! and semantic verification of codegen correctness.
//!
//! The interpreter models the cBPF instruction set used by `seccomp(SECCOMP_SET_MODE_FILTER)`:
//! - LD: load from seccomp_data into accumulator A
//! - ALU: bit operations (AND)
//! - JMP: conditional/unconditional branches (JEQ, JGT, JGE, JSET, JA)
//! - RET: return a SECCOMP_RET_* value

/// Simulated seccomp_data block for interpreter execution.
///
/// Layout (little-endian, matching kernel struct seccomp_data):
/// - offset 0: `nr` (u32) — syscall number
/// - offset 4: `arch` (u32) — AUDIT_ARCH_*
/// - offset 8–15: `ip` (u64)
/// - offset 16+: `args[0..6]` — each u64, low word first in memory
#[derive(Debug, Clone, Copy)]
pub struct SeccompData {
    pub nr: u32,
    pub arch: u32,
    pub args: [u64; 6],
}

impl SeccompData {
    /// Load a u32 from memory at absolute byte offset, little-endian.
    fn load_u32(&self, offset: u32) -> u32 {
        match offset {
            0 => self.nr,
            4 => self.arch,
            16..=47 => {
                // args[0..6], each 8 bytes
                let arg_idx = (offset - 16) / 8;
                let word_idx = (offset - 16) % 8;
                let val = self.args[arg_idx as usize];
                if word_idx == 0 {
                    (val & 0xFFFF_FFFF) as u32
                } else {
                    (val >> 32) as u32
                }
            }
            _ => 0, // Out-of-bounds reads return 0
        }
    }
}

/// Run a cBPF program against seccomp data, returning the SECCOMP_RET_* value.
///
/// # Panics
/// - If a jump target is out of bounds
/// - If an instruction has an unknown opcode
/// - If the program doesn't terminate (infinite loop, which shouldn't happen with valid input)
pub fn run(insns: &[libc::sock_filter], data: &SeccompData) -> u32 {
    let mut pc = 0usize;
    let mut a: u32 = 0;

    // BPF instruction opcodes
    let bpf_ld_w_abs: u16 = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
    let bpf_alu_and_k: u16 = (libc::BPF_ALU | libc::BPF_AND | libc::BPF_K) as u16;
    let bpf_jmp_jeq_k: u16 = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
    let bpf_jmp_jgt_k: u16 = (libc::BPF_JMP | libc::BPF_JGT | libc::BPF_K) as u16;
    let bpf_jmp_jge_k: u16 = (libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K) as u16;
    let bpf_jmp_jset_k: u16 = (libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K) as u16;
    let bpf_jmp_ja: u16 = (libc::BPF_JMP | libc::BPF_JA) as u16;
    let bpf_ret_k: u16 = (libc::BPF_RET | libc::BPF_K) as u16;

    loop {
        let insn = &insns[pc];

        match insn.code {
            code if code == bpf_ld_w_abs => {
                // LD: Load u32 from data at offset k
                a = data.load_u32(insn.k);
                pc += 1;
            }
            code if code == bpf_alu_and_k => {
                // ALU AND: A = A & k
                a &= insn.k;
                pc += 1;
            }
            code if code == bpf_jmp_jeq_k => {
                // JEQ: if A == k, jump jt; else jump jf
                pc += 1 + if a == insn.k {
                    insn.jt as usize
                } else {
                    insn.jf as usize
                };
            }
            code if code == bpf_jmp_jgt_k => {
                // JGT: if A > k, jump jt; else jump jf
                pc += 1 + if a > insn.k {
                    insn.jt as usize
                } else {
                    insn.jf as usize
                };
            }
            code if code == bpf_jmp_jge_k => {
                // JGE: if A >= k, jump jt; else jump jf
                pc += 1 + if a >= insn.k {
                    insn.jt as usize
                } else {
                    insn.jf as usize
                };
            }
            code if code == bpf_jmp_jset_k => {
                // JSET: if A & k != 0, jump jt; else jump jf
                pc += 1 + if (a & insn.k) != 0 {
                    insn.jt as usize
                } else {
                    insn.jf as usize
                };
            }
            code if code == bpf_jmp_ja => {
                // JA: unconditional jump
                pc += 1 + insn.k as usize;
            }
            code if code == bpf_ret_k => {
                // RET: return k (SECCOMP_RET_* value)
                return insn.k;
            }
            _ => panic!("Unknown BPF opcode: {}", insn.code),
        }

        // Bounds check
        if pc >= insns.len() {
            panic!(
                "BPF instruction pointer {} out of bounds (program len={})",
                pc,
                insns.len()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interp_basic_load_and_return() {
        // Minimal program: load nr, compare, return
        let insns = vec![
            libc::sock_filter {
                code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
                jt: 0,
                jf: 0,
                k: 0, // offset of nr
            },
            libc::sock_filter {
                code: (libc::BPF_RET | libc::BPF_K) as u16,
                jt: 0,
                jf: 0,
                k: libc::SECCOMP_RET_ALLOW,
            },
        ];

        let data = SeccompData {
            nr: 42,
            arch: 0,
            args: [0; 6],
        };

        let result = run(&insns, &data);
        assert_eq!(result, libc::SECCOMP_RET_ALLOW);
    }

    #[test]
    fn test_interp_conditional_jump() {
        // Load nr, compare to 1, branch on equal
        let insns = vec![
            libc::sock_filter {
                code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
                jt: 0,
                jf: 0,
                k: 0, // offset of nr
            },
            libc::sock_filter {
                code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                jt: 1, // jump to insn 3 if equal
                jf: 0, // fall through to insn 2 if not
                k: 1,  // compare to 1
            },
            libc::sock_filter {
                code: (libc::BPF_RET | libc::BPF_K) as u16,
                jt: 0,
                jf: 0,
                k: libc::SECCOMP_RET_KILL,
            },
            libc::sock_filter {
                code: (libc::BPF_RET | libc::BPF_K) as u16,
                jt: 0,
                jf: 0,
                k: libc::SECCOMP_RET_ALLOW,
            },
        ];

        // nr == 1 should return ALLOW
        let data1 = SeccompData {
            nr: 1,
            arch: 0,
            args: [0; 6],
        };
        assert_eq!(run(&insns, &data1), libc::SECCOMP_RET_ALLOW);

        // nr != 1 should return KILL
        let data2 = SeccompData {
            nr: 5,
            arch: 0,
            args: [0; 6],
        };
        assert_eq!(run(&insns, &data2), libc::SECCOMP_RET_KILL);
    }

    #[test]
    fn test_interp_load_arg() {
        // Load arg[0] low word (offset 16), compare, return
        let insns = vec![
            libc::sock_filter {
                code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
                jt: 0,
                jf: 0,
                k: 16, // offset of args[0] low word
            },
            libc::sock_filter {
                code: (libc::BPF_RET | libc::BPF_K) as u16,
                jt: 0,
                jf: 0,
                k: libc::SECCOMP_RET_ALLOW,
            },
        ];

        let data = SeccompData {
            nr: 0,
            arch: 0,
            args: [0x0000_0001_FFFF_FFFF, 0, 0, 0, 0, 0], // arg[0] = 0x0000_0001_FFFF_FFFF
        };

        let result = run(&insns, &data);
        assert_eq!(result, libc::SECCOMP_RET_ALLOW);
    }

    #[test]
    fn test_interp_alu_and() {
        // Load arg[0] low, AND with mask, compare, branch
        let insns = vec![
            libc::sock_filter {
                code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
                jt: 0,
                jf: 0,
                k: 16, // args[0] low
            },
            libc::sock_filter {
                code: (libc::BPF_ALU | libc::BPF_AND | libc::BPF_K) as u16,
                jt: 0,
                jf: 0,
                k: 0xFF,
            },
            libc::sock_filter {
                code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
                jt: 1,
                jf: 0,
                k: 0x42,
            },
            libc::sock_filter {
                code: (libc::BPF_RET | libc::BPF_K) as u16,
                jt: 0,
                jf: 0,
                k: libc::SECCOMP_RET_KILL,
            },
            libc::sock_filter {
                code: (libc::BPF_RET | libc::BPF_K) as u16,
                jt: 0,
                jf: 0,
                k: libc::SECCOMP_RET_ALLOW,
            },
        ];

        // (0x0000_00FF & 0xFF) == 0x42? No.
        let data1 = SeccompData {
            nr: 0,
            arch: 0,
            args: [0x0000_00FF, 0, 0, 0, 0, 0],
        };
        assert_eq!(run(&insns, &data1), libc::SECCOMP_RET_KILL);

        // (0x0000_0042 & 0xFF) == 0x42? Yes.
        let data2 = SeccompData {
            nr: 0,
            arch: 0,
            args: [0x0000_0042, 0, 0, 0, 0, 0],
        };
        assert_eq!(run(&insns, &data2), libc::SECCOMP_RET_ALLOW);
    }
}
