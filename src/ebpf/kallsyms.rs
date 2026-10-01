//! Kernel symbol names for off-CPU stacks, from `/proc/kallsyms`.
//!
//! Addresses there are shown only to readers the kernel trusts (root, or
//! `CAP_SYSLOG`, depending on `kernel.kptr_restrict`); otherwise every address
//! reads as zero, and stacks are left unnamed rather than misnamed.

/// Text symbols sorted by address.
#[derive(Debug, Default)]
pub struct KernelSymbols {
    syms: Vec<(u64, String)>,
}

impl KernelSymbols {
    /// Parse `/proc/kallsyms` text: `ffffffff81000000 T _stext [module]`.
    /// Keeps text symbols (`t`/`T`) with a non-zero address.
    pub fn parse(text: &str) -> Self {
        let mut syms: Vec<(u64, String)> = text
            .lines()
            .filter_map(|line| {
                let mut f = line.split_whitespace();
                let addr = u64::from_str_radix(f.next()?, 16).ok()?;
                let kind = f.next()?;
                let name = f.next()?;
                (addr != 0 && matches!(kind, "t" | "T")).then(|| (addr, name.to_string()))
            })
            .collect();
        syms.sort_unstable_by_key(|(a, _)| *a);
        Self { syms }
    }

    /// Load from `/proc/kallsyms`; `None` if unreadable or addresses are hidden.
    pub fn load() -> Option<Self> {
        let syms = Self::parse(&std::fs::read_to_string("/proc/kallsyms").ok()?);
        (!syms.syms.is_empty()).then_some(syms)
    }

    /// The function containing `addr`: the last symbol at or below it.
    pub fn resolve(&self, addr: u64) -> Option<&str> {
        let i = self.syms.partition_point(|(a, _)| *a <= addr);
        (i > 0).then(|| self.syms[i - 1].1.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
ffffffff81000000 T _stext
ffffffff81200000 t pipe_write
ffffffff81200400 T anon_pipe_write
ffffffff81300000 D some_data
ffffffff81400000 t ext4_file_write_iter\t[ext4]
0000000000000000 T hidden
";

    #[test]
    fn resolves_to_the_enclosing_function() {
        let k = KernelSymbols::parse(SAMPLE);
        assert_eq!(k.resolve(0xffffffff81200010), Some("pipe_write"));
        assert_eq!(k.resolve(0xffffffff81200400), Some("anon_pipe_write"));
        // data symbols are skipped: falls back to the preceding text symbol
        assert_eq!(k.resolve(0xffffffff81300010), Some("anon_pipe_write"));
        assert_eq!(k.resolve(0xffffffff81400020), Some("ext4_file_write_iter"));
        assert_eq!(k.resolve(0x1000), None);
    }

    #[test]
    fn hidden_addresses_give_no_symbols() {
        // kptr_restrict: every address reads as zero
        let k = KernelSymbols::parse("0000000000000000 T _stext\n0000000000000000 t pipe_write\n");
        assert_eq!(k.resolve(0xffffffff81200010), None);
    }
}
