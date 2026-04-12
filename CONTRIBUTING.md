# Contributing to App Mesh

Thank you for your interest in contributing to App Mesh! This document provides guidelines and information for contributors.

## Getting Started

### Prerequisites

- Linux (Ubuntu 22.04+ recommended), macOS, or Windows
- C++17 compatible compiler (GCC 8+, Clang 10+, MSVC 2019+)
- CMake 3.21+
- Git

### Building from Source

```bash
# Clone the repository
git clone https://github.com/laoshanxi/app-mesh.git
cd app-mesh

# Install build dependencies (Ubuntu)
# See script/setup_build_env/ for platform-specific setup

# Build
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

# Run tests
make test ARGS="-V"
```

### Docker Build (No Local Dependencies)

```bash
docker run --rm -v $(pwd):$(pwd) -w $(pwd) laoshanxi/appmesh:build_ubuntu22 \
  sh -c "mkdir build && cd build && cmake .. && make && make pack"
```

## How to Contribute

### Reporting Bugs

- Check [existing issues](https://github.com/laoshanxi/app-mesh/issues) first
- Use the bug report template when creating a new issue
- Include: steps to reproduce, expected behavior, actual behavior, environment details

### Suggesting Features

- Open a feature request issue using the template
- Describe the use case and expected behavior

### Submitting Changes

1. Fork the repository
2. Create a feature branch from `main` (`git checkout -b feature/my-feature`)
3. Make your changes
4. Ensure all tests pass
5. Submit a pull request

### Pull Request Guidelines

- Keep PRs focused on a single change
- Update tests for new functionality
- Follow the existing code style (see below)
- Reference related issues in the PR description

## Code Style

### C++ (Core Daemon and CLI)

- **Standard**: C++17
- **Classes**: CamelCase (e.g., `ApplicationManager`)
- **Logging**: Use `LOG_DBG`, `LOG_INF`, `LOG_WAR`, `LOG_ERR` macros from `StreamLogger.h`
- **Warnings**: Code must compile with `-Wall` enabled
- **Static Analysis**: Must pass cpplint and Coverity checks

### SDK Languages

- **Python**: Follow PEP 8, checked by pylint
- **Go**: Follow standard Go conventions, checked by golangci-lint
- **JavaScript**: Follow ESLint configuration
- **Java**: Follow Checkstyle configuration
- **Rust**: Follow standard Rust conventions (`cargo fmt`, `cargo clippy`)

### Shell Scripts

- Must pass shellcheck

## Pre-commit Hooks

This project uses pre-commit hooks for code quality. Install them before committing:

```bash
pip install pre-commit
pre-commit install
```

The hooks run: cpplint, pylint, golangci-lint, shellcheck, eslint, Checkstyle, and gitleaks (secret detection).

## Commit Messages

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
type(scope): description

[optional body]
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`, `perf`, `ci`

Examples:
- `feat(cli): add output format option for ls command`
- `fix(daemon): resolve memory leak in application monitor`
- `docs: update REST API examples`

## Testing

- **C++ Tests**: Catch2 framework via CTest (`make test ARGS="-V"`)
- **Python SDK**: `python3 -m unittest --verbose` (from `src/sdk/python/test/`)
- **Go SDK**: `go test ./src/sdk/go/ -test.v`
- **Static Analysis**: `make cppcheck`

## License

By contributing to App Mesh, you agree that your contributions will be licensed under the [MIT License](LICENSE).
