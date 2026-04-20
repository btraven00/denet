# Portability

What you need on the build host and at runtime to use denet, especially
with the `ebpf` feature.

## Non-eBPF builds

`cargo build` (no features) works on any platform Rust supports. The
monitor's `/proc`-based metrics are Linux-only; on other platforms it
falls back to `sysinfo`-based data.

## eBPF builds (`--features ebpf`)

### Build host

- **OS:** Linux only.
- **Toolchain:** `clang` with BPF target support.
  - Ubuntu/Debian: `sudo apt install clang`
  - RHEL/Fedora: `sudo dnf install clang`
  - Arch: `sudo pacman -S clang`
  - Alpine: `apk add clang`
- **Kernel UAPI headers:** `<linux/bpf.h>`, `<linux/ptrace.h>`,
  `<linux/types.h>`, `<asm/types.h>`.
  - Debian/Ubuntu: shipped by `linux-libc-dev` (usually pulled in by
    `build-essential` / `libc6-dev`).
  - RHEL/Fedora: shipped by `kernel-headers`.
  - Arch: in `linux-api-headers` (installed with base-devel).
  - Alpine: `apk add linux-headers`.
- **libbpf headers:** *not required* — vendored at
  `src/ebpf/include/bpf/` (libbpf 1.3.0, LGPL-2.1 / BSD-2-Clause). See
  `src/ebpf/include/bpf/UPSTREAM.md` for provenance and update process.

`build.rs` handles arch detection automatically (`CARGO_CFG_TARGET_ARCH`)
and probes for the Debian multiarch include path
(`/usr/include/<triple>/`) for `<asm/types.h>`. On flat-layout distros
(RHEL/Arch/Alpine) where headers live directly under `/usr/include/`, no
multiarch path is needed and the probe simply skips it.

### Runtime

The compiled `.o` eBPF bytecode is embedded in the denet binary via
`include_bytes!`. At runtime, the target kernel must meet these
conditions:

| Requirement | Reason | Typical status |
|---|---|---|
| `CONFIG_BPF_SYSCALL=y` | Load BPF programs | Enabled on all mainstream distro kernels |
| `CONFIG_KPROBES=y`, `CONFIG_KRETPROBES=y` | Attach kretprobes | Enabled on all mainstream distro kernels |
| `CONFIG_TRACEPOINTS=y` | Attach tracepoints | Always on when tracing subsystem is compiled |
| Kernel ≥ 4.15 (practical floor) | Verifier + BTF maturity | Anything shipped since ~2018 |
| Target kprobe symbols exist | `tcp_sendmsg`, `tcp_recvmsg`, etc. | Stock kernels yes; stripped/embedded may differ |
| `CAP_BPF` (≥ 5.8) or root | Load programs | Deployment concern, not build |

### What isn't portable

- **Architecture.** One binary per `{os, arch}`. An x86_64 build produces
  x86_64 bytecode; aarch64 needs its own build.
- **Kernel bytecode portability.** The `.o` doesn't use CO-RE
  relocations. It works across kernels only because none of denet's
  programs read kernel struct fields — just stable helpers, maps,
  tracepoints, and well-known kprobe symbols. The moment a program
  starts dereferencing e.g. `struct sock`, we'll need `vmlinux.h` +
  `BPF_CORE_READ()` and a `-g` build with relocations. Not required
  today; budget it for whenever field-reads get added.
- **macOS / Windows.** No kprobes, no tracepoints, no BPF. Build
  without `--features ebpf`.

### Known gotchas

- **Custom / hardened kernels** may strip kprobe symbols
  (`/proc/kallsyms` missing `tcp_sendmsg` etc.). denet logs a warning
  and falls back to `/proc`-based metrics; the feature degrades rather
  than crashing.
- **Verifier variance across versions.** A program that verifies on 6.x
  *usually* verifies on 4.19, but not guaranteed. If you support old
  kernels, test-load on the oldest one you care about.
- **`kptr_restrict`, `unprivileged_bpf_disabled`, `perf_event_paranoid`**
  affect non-root runs. See `docs/ebpf.md` for the settings.

## Cross-compilation

Not wired up yet. The `build.rs` probes the *build host's*
`/usr/include/` for kernel UAPI headers — it doesn't redirect to a
sysroot. If you need aarch64 binaries, build on an aarch64 host (or in
an aarch64 container via binfmt/qemu). Adding sysroot support would
require either:

- propagating `CC_aarch64_unknown_linux_gnu` / `--sysroot` flags into
  the clang invocation, or
- vendoring `<linux/bpf.h>` too so nothing outside the repo is needed.

Open an issue if you need this.
