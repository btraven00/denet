# Changelog

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
