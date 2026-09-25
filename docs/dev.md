# Developer Documentation

This document contains information for developers working on the denet project, including development setup, workflows, and release processes.

> **New here?** Start with [docs/architecture.md](architecture.md) for the data-flow diagram and a walkthrough of how a sample travels from the monitored process tree through the collectors and the adaptive sampling loop to the JSONL stream and the three interfaces. This document covers how to build and release the code; that one covers how it fits together.

## Requirements

- Python 3.9+
- Rust (for development)
- [pixi](https://prefix.dev/docs/pixi/overview) (for development only)
- **eBPF features**: Linux kernel 5.5+, `clang` at build time, `CAP_BPF` + `CAP_PERFMON` or root at runtime

## Development Environment

Denet follows a Rust-first development approach, with Python bindings as a secondary interface.

### Setting Up the Development Environment

1. Clone the repository
2. Install pixi if you don't have it already: [Pixi Installation Guide](https://prefix.dev/docs/pixi/overview)
3. Set up the development environment:

```bash
pixi install
```

### Development Workflow

1. Make changes to Rust code in `src/`
2. Test with Cargo: `pixi run test-rust`
3. Build and install Python bindings: `pixi run develop`
4. Test Python bindings: `pixi run test`

## Testing

### Running Tests

```bash
# Run Rust tests only (primary development testing)
pixi run test-rust

# Run Python tests only (after building with "develop")
pixi run test

# Run all tests together
pixi run test-all
```

### Pre-release hardware check

CI can't exercise GPU, RAPL or eBPF end to end. Before tagging, run this on a Linux machine with a GPU:

```bash
./scripts/release_check.sh              # uses sudo; kernel matrix needs virtme-ng
./scripts/release_check.sh '/boot/vmlinuz-6.8*'   # limit the kernel matrix
```

### Linting and Formatting

```bash
# Lint Python code
pixi run lint

# Fix linting issues automatically
pixi run lint-fix

# Format Rust and Python code
pixi run fmt
```

### Testing Strategy

- **Unit Tests:** Test individual components in isolation
- **Integration Tests:** Test interactions between components
- **Regression Tests:** Ensure bugs don't reappear
- **Cross-platform Tests:** Verify functionality on different OSes

## Continuous Integration

The project uses GitHub Actions for CI/CD. The workflows are defined in `.github/workflows/`:

- **test.yml:** Runs tests on multiple platforms and Python versions
- **release-please.yml:** Opens the release PR (CHANGELOG only) and tags the release when it merges
- **publish.yml:** Builds wheels (Linux manylinux_2_28 with eBPF, macOS) and the sdist, then publishes to PyPI when a release is created
- **conda-release.yml:** Publishes the conda package to prefix.dev on `v*` tags

### Testing GitHub Actions Locally

You can test GitHub Actions workflows locally using [act](https://github.com/nektos/act):

```bash
# Test all workflows
./scripts/test_github_actions.sh

# Test a specific workflow
./scripts/test_github_actions.sh --workflow test.yml

# Test on a specific platform
./scripts/test_github_actions.sh --platform ubuntu-latest

# Test a specific event
./scripts/test_github_actions.sh --event pull_request
```

## Helper Scripts

The project includes scripts to help with development:

```bash
# Build and install the extension in the current Python environment
./scripts/build_and_install.sh

# Update version numbers across the project
./scripts/update_version.sh 0.1.2

# Check code style and lint
pixi run lint

# Fix code style issues automatically
pixi run lint-fix

# Format both Rust and Python code
pixi run fmt
```

## Project Structure

For what these components *do* and how they relate at runtime, see
[docs/architecture.md](architecture.md); the tree below is a build-level
orientation only.

```
denet/
├── src/              # Rust source code (primary development focus)
│   ├── lib.rs        # Library root
│   ├── python.rs     # PyO3 bindings
│   ├── bin/          # CLI (denet.rs) and diagnostic binaries
│   ├── core/         # Process tree discovery and per-process sampling
│   ├── monitor/      # Metrics, Summary, JSONL records, env capture
│   ├── cpu_sampler.rs, perf/, psi/, rapl/   # Linux collectors
│   ├── gpu/          # NVML collector (feature: gpu)
│   ├── ebpf/         # eBPF collectors and BPF programs (feature: ebpf)
│   └── symbolication/  # Stack symbolication for off-CPU profiling
├── python/denet/     # Python package
│   ├── __init__.py   # Python API (ProcessMonitor, execute_with_monitoring)
│   ├── analysis.py   # Analysis utilities
│   └── report.py     # denet-report (HTML/PNG/SVG)
├── tests/            # Rust integration tests (*.rs)
│   ├── python/       # Python binding tests
│   └── cli/          # Command-line interface tests
├── .github/workflows/  # CI, release and publish workflows
├── scripts/          # Helper scripts for development
├── Cargo.toml        # Rust dependencies and configuration
└── pyproject.toml    # Python build configuration (maturin) and pixi tasks
```

## Release Process

Releases are driven by [release-please](https://github.com/googleapis/release-please) from conventional commits on `main`.

1. release-please keeps a release PR open that updates `CHANGELOG.md`. It does **not** bump package versions (`release-type: simple`).

2. Before merging it, bump the version everywhere in a separate PR to `main`. Don't push to the release-please branch, because it gets regenerated and your commit is lost:
   ```bash
   ./scripts/update_version.sh X.Y.Z
   cargo update -p denet   # refresh Cargo.lock
   ```

3. Merge the release PR. release-please tags `vX.Y.Z` and creates the GitHub release.

4. The release triggers `publish.yml` (PyPI) and the tag triggers `conda-release.yml` (prefix.dev).

To rebuild a release by hand, run `gh workflow run publish.yml --ref main`.

## Stack Traces and Symbolication

When eBPF off-CPU profiling is enabled, denet captures user-space stack IDs via `bpf_get_stackid()` and resolves them to symbol names in userspace. Symbolication reads `/proc/{pid}/maps` to find loaded shared libraries and executables, then invokes `addr2line` to map instruction addresses to function names and source locations.

For best results:

- Build monitored programs with debug symbols (`-g`). Without DWARF info, symbolication falls back to raw hex addresses.
- JIT-compiled languages (Python, Java, Node.js) show JIT trampolines rather than source-level frames. Use frame pointer compilation flags or language-specific debug packages for better results.
- Kernel stacks require `CONFIG_BPF_STACK_TRACE` and are not collected by default.

See `docs/offcpu.md` for the full off-CPU architecture and known limitations.

## Code Style

### Rust

- Follow the [Rust Style Guide](https://doc.rust-lang.org/style-guide/)
- Use `cargo fmt` to format code
- Use `cargo clippy` to catch common mistakes

### Python

- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/)
- Use type hints for function signatures
- Document functions and classes with docstrings
- Use `ruff` for linting and formatting (configured in `pyproject.toml`)
- Run `pixi run lint` to check for issues and `pixi run lint-fix` to automatically fix issues