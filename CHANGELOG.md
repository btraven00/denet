# Changelog

## [0.6.0](https://github.com/btraven00/denet/compare/v0.5.0...v0.6.0) (2026-04-22)


### Features

* expose syscall I/O and page-fault counters for cache/mmap visibility ([#23](https://github.com/btraven00/denet/issues/23)) ([070e0b9](https://github.com/btraven00/denet/commit/070e0b908dc90b40d702055db241105f657a6ca1))
* **summary:** add SyscallIntensitySummary to Summary ([36b2316](https://github.com/btraven00/denet/commit/36b2316d4107fc5081618fcd727d92d18a5627f3))


### Bug Fixes

* add serde aliases for renamed net_rx/tx_bytes fields and update test assertions ([2c62fe1](https://github.com/btraven00/denet/commit/2c62fe11b9fff0c7d231b2a26fc65463d3bc5726))
* **cli:** remove default out.json dump, require explicit --out PATH ([d820cb3](https://github.com/btraven00/denet/commit/d820cb37c4b83831ffec49528e3f69894d7b3eae))
* eBPF tracepoint and document capabilities ([#21](https://github.com/btraven00/denet/issues/21)) ([4ac2872](https://github.com/btraven00/denet/commit/4ac2872a931c4fdc6399d0933864cf7244aaed21))
* **ebpf:** remove duplicate refresh_maps_for_pid calls in OffCpuProfiler constructor ([2722ea7](https://github.com/btraven00/denet/commit/2722ea764e8e135a0690cde302e32bb5c859d444))
* thread aggregation double count ([#24](https://github.com/btraven00/denet/issues/24)) ([c6cfe42](https://github.com/btraven00/denet/commit/c6cfe420da66ab02080c6ef9c0d1570fc72a8d5e))

## [0.5.0](https://github.com/btraven00/denet/compare/v0.4.2...v0.5.0) (2026-04-14)


### Features

* **ebpf:** add off-CPU profiler module (no integration yet) ([2b5a46e](https://github.com/btraven00/denet/commit/2b5a46e9da014c897d99f3e791db72fc3a3d3a48))
* **ebpf:** wire off-CPU profiler into ProcessMonitor ([ccf670d](https://github.com/btraven00/denet/commit/ccf670d8823961e7de1f375133a740547582d0c1))
* **gpu:** add NVIDIA GPU monitoring support ([bd1a942](https://github.com/btraven00/denet/commit/bd1a9423947ea4ebc92df2838a9165225fcf2d96))


### Bug Fixes

* **build:** remove spurious cargo:warning= from informational build messages ([66803d9](https://github.com/btraven00/denet/commit/66803d9b4965c07a63703b1c94ebb60fb1621f8a))
* **cli:** add gpu report to summary and progress ([#16](https://github.com/btraven00/denet/issues/16)) ([e335c2e](https://github.com/btraven00/denet/commit/e335c2efde50555dc16695f54c17d82818e3e41a))
* **cli:** suppress UI output in --json mode; fix summary table alignment ([9d28cef](https://github.com/btraven00/denet/commit/9d28cef5e0dfa6c02444fde9e427f907907a9f3e))
* **ebpf:** correct PID attribution in off-CPU events ([b45553f](https://github.com/btraven00/denet/commit/b45553ff125a145b9208831c2e78ef2a0ec19647))
* **ebpf:** return empty syscall metrics instead of error for zero-syscall workloads ([08372c7](https://github.com/btraven00/denet/commit/08372c7e5fee027cd3cff0865e7e0f142af7f922))

## [0.4.2](https://github.com/btraven00/denet/compare/v0.4.1...v0.4.2) (2025-07-07)


### Bug Fixes

* **build:** allow to build in osx ([b38d333](https://github.com/btraven00/denet/commit/b38d33327864c2345c9999eaf34bf3f2e10c823e))

## [0.4.1](https://github.com/btraven00/denet/compare/v0.4.0...v0.4.1) (2025-06-23)


### Miscellaneous Chores

* update version to 0.4.1 ([b3591b5](https://github.com/btraven00/denet/commit/b3591b54c36f41a91867d4abb67d4db4308ac2fd))

## [0.4.0](https://github.com/btraven00/denet/compare/v0.3.3...v0.4.0) (2025-06-23)


### Features

* allow to write metadata line from monitoring function ([ea81d00](https://github.com/btraven00/denet/commit/ea81d00b7a9d09e44f8b2f95af6bd114e2493d15))
* **docs:** comment on subprocess.run compat ([d60fb1f](https://github.com/btraven00/denet/commit/d60fb1f881aa303cfd69e2f6e3f67d6e0ba6ab19))


### Bug Fixes

* **docs:** remove outdated comment ([79d08b3](https://github.com/btraven00/denet/commit/79d08b3169eb01a44247de4b4a99b3e900c31a92))

## [0.3.3](https://github.com/btraven00/denet/compare/v0.3.2...v0.3.3) (2025-06-21)


### Bug Fixes

* **docs:** format ([df9415b](https://github.com/btraven00/denet/commit/df9415b7feea8aa75c52f5088c81069697de6b06))
* **tests:** exclude python module ([bfe62d5](https://github.com/btraven00/denet/commit/bfe62d5dc9641ab261d266dadf1c142c2e86eb79))
* **tests:** refactor python test suite ([2aeb5ed](https://github.com/btraven00/denet/commit/2aeb5eda6bf4d1e4fa9fbea01130cbf5281445c3))

## [0.3.2](https://github.com/btraven00/denet/compare/v0.3.1...v0.3.2) (2025-06-19)


### Bug Fixes

* **python:** expose child process monitoring ([7033251](https://github.com/btraven00/denet/commit/70332513a5cf20208601f6a418946f8873387548))

## [0.3.1](https://github.com/btraven00/denet/compare/v0.3.0...v0.3.1) (2025-06-19)


### Bug Fixes

* **docs:** bump the version internally ([2ed414e](https://github.com/btraven00/denet/commit/2ed414e87e3fec3ee1d1d09fca8310653a629986))

## [0.3.0](https://github.com/btraven00/denet/compare/v0.2.1...v0.3.0) (2025-06-19)


### Features

* add eBPF profiling integration for syscall tracking ([42a428d](https://github.com/btraven00/denet/commit/42a428d0e2d67c7bbf8a8440f90aeefe5f96b8da))
* implement execute_with_monitoring with signal-based process control ([a2410b4](https://github.com/btraven00/denet/commit/a2410b4f33c6de10a5526990e075e15554de3237))


### Bug Fixes

* **perf:** optimize ProcessMonitor initialization by avoiding expensive system-wide scans ([1bed5ad](https://github.com/btraven00/denet/commit/1bed5ad33af702d59403d0f1f5907738df40874c))
* **tests:** fix tests and build issues, convert to pytest ([f76db7f](https://github.com/btraven00/denet/commit/f76db7fe3fa8426b099bbe607582da870cb40264))
* update adaptive sampling test expectations to account for sampling overhead ([b01ce33](https://github.com/btraven00/denet/commit/b01ce3356332546d42f53ac4f3838dd0d2a92b6c))

## 0.2.1 (2025-06-13)

### Code Refactoring

* migrate to modular architecture ([87fb729](https://github.com/btraven00/denet/commit/87fb7292126da6bbad99734a8eedf99882297bdc))

## 0.2.0 (2025-06-12)


### Features

* add cli utility ([8f4525a](https://github.com/btraven00/denet/commit/8f4525accd7e0917c75d714e62c3b0f645c6e611))
* add execution summary ([cf605da](https://github.com/btraven00/denet/commit/cf605da17d865951583cad0998c55269df512ae9))
* attach to PID ([edf962a](https://github.com/btraven00/denet/commit/edf962aca1375ee695f480405913d90ebfe43972))
* child process monitoring ([fd6f444](https://github.com/btraven00/denet/commit/fd6f444a7e6884b5c199565bd6fb6bbce374e9f3))
* improve CPU measurement accuracy with direct procfs integration ([acac9c1](https://github.com/btraven00/denet/commit/acac9c1c6bce1606400643fa20a4e9e1d3d1805f))
* improve python API ([4ba1006](https://github.com/btraven00/denet/commit/4ba10063e28f0909c99f049e3e35bca1b6c25a8b))
* improve terminal output ([35eb029](https://github.com/btraven00/denet/commit/35eb0291c3eed658ba8213963dc4c9bd93348384))
* metadata separation ([6d0533d](https://github.com/btraven00/denet/commit/6d0533d33c8c0d517baf8f152b0c0b182a8b65aa))
* separate i/o from start of process ([27e24bc](https://github.com/btraven00/denet/commit/27e24bce7cf6c285f480770272f617b31b8db477))
* split network and disk i/o ([f8f3d53](https://github.com/btraven00/denet/commit/f8f3d53c2b8b568363e83164ab57dc4fbcc0ca03))


### Bug Fixes

* account for delta io in children tree ([b9ec550](https://github.com/btraven00/denet/commit/b9ec5507819adbc0168216651bae99d91bfa4a71))
