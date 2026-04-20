# Vendored libbpf headers

These headers are vendored verbatim from libbpf so that building denet's
eBPF programs does not require `libbpf-dev` (Debian/Ubuntu) /
`libbpf-devel` (RHEL/Fedora) / `libbpf-dev` (Alpine) to be installed on
the build host.

## Source

- **Upstream:** <https://github.com/libbpf/libbpf>
- **Version:** 1.3.0 (from Debian package `libbpf-dev 1:1.3.0-2build2`)
- **Files:**
  - `bpf_helpers.h`
  - `bpf_tracing.h`
  - `bpf_helper_defs.h` (auto-generated from kernel `bpf.h`)

## License

Dual-licensed `LGPL-2.1 OR BSD-2-Clause` (SPDX identifiers preserved in
each file header). Compatible with denet's `GPL-3.0-or-later`.

## Updating

When updating, replace these files verbatim from an upstream libbpf
release of your choice and bump the version noted above. Do not modify
them locally — if you need to patch behavior, add a separate header in
`src/ebpf/programs/` that includes these.

## What still needs to come from the system

`<linux/bpf.h>`, `<linux/ptrace.h>`, `<linux/types.h>` — kernel UAPI
headers from `linux-libc-dev` (or equivalent). These are part of the
standard C development environment on every mainstream Linux distro, so
vendoring them is not worth the maintenance cost.
