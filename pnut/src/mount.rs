//! Mount configuration types for the sandbox.
//!
//! [`MountEntry`] is a tagged enum matching pnut-child's mount types.
//! [`Table`] accumulates entries in order via builder methods.

use std::slice;

/// Proc mount `subset=` option.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcSubset {
    /// `subset=pid` — only PID-related entries are visible.
    Pid,
}

/// Proc mount `hidepid=` option.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HidePid {
    /// `hidepid=0` — all `/proc/<pid>` directories are visible to everyone.
    Visible,
    /// `hidepid=1` — users cannot access other users' `/proc/<pid>` contents.
    Hidden,
    /// `hidepid=2` / `hidepid=invisible` — other users' `/proc/<pid>` directories
    /// are completely invisible.
    Invisible,
}

/// One filesystem mount operation.
#[derive(Debug, Clone)]
pub enum MountEntry {
    Bind {
        src: String,
        dst: String,
        read_only: bool,
    },
    Tmpfs {
        dst: String,
        size: Option<u64>,
        /// Octal file mode (e.g., `0o1777`, `0o755`).
        mode: Option<u32>,
        read_only: bool,
    },
    Proc {
        dst: String,
        subset: Option<ProcSubset>,
        hidepid: Option<HidePid>,
    },
    Mqueue {
        dst: String,
    },
    File {
        dst: String,
        content: String,
        read_only: bool,
    },
}

/// Ordered filesystem mount operations for a sandbox.
#[derive(Debug, Default)]
pub struct Table {
    entries: Vec<MountEntry>,
}

impl Table {
    /// Create an empty mount table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append one mount entry.
    pub fn push(&mut self, entry: MountEntry) -> &mut Self {
        self.entries.push(entry);
        self
    }

    /// Append many mount entries.
    pub fn extend<I>(&mut self, entries: I) -> &mut Self
    where
        I: IntoIterator<Item = MountEntry>,
    {
        self.entries.extend(entries);
        self
    }

    /// Add a recursive bind mount.
    pub fn bind(&mut self, src: impl Into<String>, dst: impl Into<String>) -> &mut Self {
        self.push(MountEntry::Bind {
            src: src.into(),
            dst: dst.into(),
            read_only: false,
        })
    }

    /// Add a read-only recursive bind mount.
    pub fn bind_read_only(&mut self, src: impl Into<String>, dst: impl Into<String>) -> &mut Self {
        self.push(MountEntry::Bind {
            src: src.into(),
            dst: dst.into(),
            read_only: true,
        })
    }

    /// Add a tmpfs mount at the destination path.
    pub fn tmpfs(&mut self, dst: impl Into<String>) -> &mut Self {
        self.push(MountEntry::Tmpfs {
            dst: dst.into(),
            size: None,
            mode: None,
            read_only: false,
        })
    }

    /// Add a tmpfs mount with explicit size and mode.
    pub fn tmpfs_with_options(
        &mut self,
        dst: impl Into<String>,
        size: Option<u64>,
        mode: Option<u32>,
    ) -> &mut Self {
        self.push(MountEntry::Tmpfs {
            dst: dst.into(),
            size,
            mode,
            read_only: false,
        })
    }

    /// Add a procfs mount with default hardening (`subset=pid`, `hidepid=invisible`).
    pub fn proc(&mut self, dst: impl Into<String>) -> &mut Self {
        self.push(MountEntry::Proc {
            dst: dst.into(),
            subset: Some(ProcSubset::Pid),
            hidepid: Some(HidePid::Invisible),
        })
    }

    /// Add an mqueue mount.
    pub fn mqueue(&mut self, dst: impl Into<String>) -> &mut Self {
        self.push(MountEntry::Mqueue { dst: dst.into() })
    }

    /// Inject a file into the sandbox filesystem.
    pub fn inject_file(&mut self, dst: impl Into<String>, content: impl Into<String>) -> &mut Self {
        self.push(MountEntry::File {
            dst: dst.into(),
            content: content.into(),
            read_only: false,
        })
    }

    /// Inject a read-only file into the sandbox filesystem.
    pub fn inject_read_only_file(
        &mut self,
        dst: impl Into<String>,
        content: impl Into<String>,
    ) -> &mut Self {
        self.push(MountEntry::File {
            dst: dst.into(),
            content: content.into(),
            read_only: true,
        })
    }

    /// Iterate over mount entries in insertion order.
    pub fn iter(&self) -> slice::Iter<'_, MountEntry> {
        self.entries.iter()
    }

    /// Return the number of mount entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl<'a> IntoIterator for &'a Table {
    type Item = &'a MountEntry;
    type IntoIter = slice::Iter<'a, MountEntry>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter()
    }
}
