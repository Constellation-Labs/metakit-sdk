# Contributing to Constellation Metagraph SDK

Thank you for your interest in contributing to the Constellation Metagraph SDK!

## Development Setup

### Prerequisites

- Node.js 18+ (TypeScript)
- Python 3.10+ (Python)
- Rust 1.70+ (Rust)
- Go 1.18+ (Go)
- Java 11+ and Maven 3.8+ (Java)
- Git

### Getting Started

1. Fork and clone the repository:
   ```bash
   git clone https://github.com/YOUR_USERNAME/metakit-sdk.git
   cd metakit-sdk
   ```

2. Install dependencies:
   ```bash
   # All languages
   make install

   # Or individually:
   make install-ts      # TypeScript
   make install-py      # Python (creates venv)
   make install-go      # Go
   make install-java    # Java (managed by Maven)
   # Rust uses Cargo, no install needed
   ```

3. Run tests to verify setup:
   ```bash
   make test
   ```

## Development Workflow

### Making Changes

1. Create a feature branch:
   ```bash
   git checkout -b feature/my-feature
   ```

2. Make your changes

3. Run tests and linting:
   ```bash
   make test
   make lint
   ```

4. Commit your changes with a descriptive message

5. Push and create a pull request

### Code Style

#### TypeScript
- Use Prettier for formatting (`make format-ts`)
- Use ESLint for linting (`make lint-ts`)
- Write tests for new functionality

#### Python
- Use Black for formatting
- Use isort for import sorting
- Use Ruff for linting (`make lint-py`)
- Use mypy for type checking
- Write tests for new functionality

#### Rust
- Use rustfmt for formatting (`make format-rs`)
- Use clippy for linting (`make lint-rs`)
- Write tests for new functionality

#### Go
- Use gofmt for formatting (`make format-go`)
- Use go vet for linting (`make lint-go`)
- Write tests for new functionality

#### Java
- Follow standard Java conventions
- Write tests for new functionality

## Testing

### Running Tests

```bash
# All tests
make test

# Individual languages
make test-ts         # TypeScript
make test-py         # Python
make test-rs         # Rust
make test-go         # Go
make test-java       # Java

# Cross-language compatibility tests
cd packages/typescript && npm test -- --testPathPattern=cross-language
cd packages/python && pytest tests/test_cross_language.py
cd packages/rust && cargo test --test cross_language
cd packages/go && go test -v -run CrossLanguage
cd packages/java && mvn test -Dtest=CrossLanguageTest
```

### Cross-Language Compatibility

When modifying signing or hashing logic, ensure that:

1. All test vectors in `/shared/test_vectors.json` still pass
2. All language implementations produce identical results
3. Signatures are interoperable between all languages

## Pull Request Guidelines

1. **Title**: Use a clear, descriptive title
2. **Description**: Explain what changes you made and why
3. **Tests**: Include tests for new functionality
4. **Documentation**: Update relevant documentation
5. **Changelog**: Add an entry to the package's CHANGELOG.md

## Reporting Issues

When reporting issues, please include:

1. SDK version and language (TypeScript/Python/Rust/Go/Java)
2. Runtime version (Node.js/Python/Rust/Go/Java)
3. Operating system
4. Steps to reproduce
5. Expected vs actual behavior
6. Any error messages or stack traces

## Release Process

Releases are managed by maintainers. The process is:

1. Update version in package config
2. Update CHANGELOG.md
3. Create PR and merge to main
4. Create GitHub Release with appropriate tag:
   - TypeScript: `typescript-v1.2.3`
   - Python: `python-v1.2.3`
   - Rust: `rust-v1.2.3`
   - Go: `packages/go/v1.2.3`
   - Java: `java-v1.2.3`
5. GitHub Actions automatically publishes to package registries

## Questions?

If you have questions, feel free to:
- Open a GitHub issue
- Reach out on the Constellation Network Discord

## License

By contributing, you agree that your contributions will be licensed under the Apache-2.0 License.