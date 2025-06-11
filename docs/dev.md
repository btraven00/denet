# Developer Documentation

This document contains information for developers working on the denet project, including development setup, workflows, and release processes.

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
- **publish.yml:** Publishes packages to PyPI on release

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

# Run tests in CI environment
./ci/run_tests.sh

# Check code style and lint
pixi run lint

# Fix code style issues automatically
pixi run lint-fix

# Format both Rust and Python code
pixi run fmt
```

## Project Structure

```
denet/
├── src/              # Rust source code (primary development focus)
│   ├── lib.rs        # Core library and Python binding interface (PyO3)
│   ├── bin/          # CLI executables
│   │   └── denet.rs  # Command-line interface implementation
│   └── process_monitor.rs  # Core implementation with Rust tests
├── python/           # Python package
│   └── denet/        # Python module
│       ├── __init__.py    # Python API (decorator and context manager)
│       └── analysis.py    # Analysis utilities
├── tests/            # Tests
│   ├── python/       # Python binding tests
│   │   ├── test_convenience.py  # Tests for decorator and context manager
│   │   └── test_process_monitor.py  # Tests for ProcessMonitor class
│   └── cli/          # Command-line interface tests
├── .github/          # GitHub configuration
│   └── workflows/    # GitHub Actions workflows for CI/CD
├── ci/               # Continuous Integration scripts
├── scripts/          # Helper scripts for development
├── Cargo.toml        # Rust dependencies and configuration
└── pyproject.toml    # Python build configuration (maturin settings)
```

## Release Process

1. Update version numbers:
   ```bash
   ./scripts/update_version.sh X.Y.Z
   ```

2. Update CHANGELOG.md with the changes in the new version

3. Commit the changes:
   ```bash
   git commit -am "Bump version to X.Y.Z"
   ```

4. Create a tag:
   ```bash
   git tag -a vX.Y.Z -m "Version X.Y.Z"
   ```

5. Push changes and tags:
   ```bash
   git push && git push --tags
   ```

6. Create a GitHub release
   - Go to Releases on the GitHub repository
   - Draft a new release
   - Choose the tag you just created
   - Add release notes
   - Publish release

7. The GitHub Actions workflow will automatically build and publish to PyPI

## Code Style

### Rust

- Follow the [Rust Style Guide](https://doc.rust-lang.org/1.0.0/style/README.html)
- Use `cargo fmt` to format code
- Use `cargo clippy` to catch common mistakes

### Python

- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/)
- Use type hints for function signatures
- Document functions and classes with docstrings
- Use `ruff` for linting and formatting (configured in `pyproject.toml`)
- Run `pixi run lint` to check for issues and `pixi run lint-fix` to automatically fix issues