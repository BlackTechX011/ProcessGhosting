# Contributing to ProcessGhosting

First off, thank you for considering contributing to ProcessGhosting! 🎉

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Commit Guidelines](#commit-guidelines)
- [Testing](#testing)
- [Documentation](#documentation)

---

## Code of Conduct

This project and everyone participating in it is governed by our Code of Conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to the repository maintainers.

**Key Principles:**
- Be respectful and inclusive
- Focus on security research and education
- Use this tool only for legal, authorized purposes
- No malicious use or encouraging illegal activities

---

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues. When creating a bug report, include:

- **Use a clear title** that describes the issue
- **Describe exact steps** to reproduce the problem
- **Provide specific examples** including code samples
- **Describe the behavior** you observed and expected
- **Include system details** (Windows version, architecture, Rust version)

Use the bug report template in GitHub Issues.

### Suggesting Features

Feature suggestions are welcome! Please:

- **Check existing feature requests** first
- **Provide a clear use case** for the feature
- **Explain how it aligns** with the project goals
- **Consider security implications**

Use the feature request template in GitHub Issues.

### Documentation Improvements

Documentation improvements are always appreciated:

- Fix typos or grammar
- Clarify unclear explanations
- Add missing information
- Improve code examples
- Update outdated information

### Code Contributions

We welcome code contributions! See the sections below for details.

---

## Development Setup

### Prerequisites

- **Rust 1.70.0 or later**
- **Windows OS** (required for testing)
- **Git**
- **Visual Studio Build Tools** (for Windows)

### Clone and Build

```bash
# Clone the repository
git clone https://github.com/BlackTechX011/ProcessGhosting-rs.git
cd ProcessGhosting-rs/ProcessGhosting

# Build
cargo build

# Run tests
cargo test

# Run examples
cargo run --example basic_usage

# Build documentation
cargo doc --open
```

### Project Structure

```
ProcessGhosting-rs/
├── .github/              # GitHub configuration
│   ├── workflows/        # CI/CD workflows
│   └── ISSUE_TEMPLATE/   # Issue templates
├── ProcessGhosting/      # Main Rust project
│   ├── src/              # Source code
│   │   ├── lib.rs        # Library entry point
│   │   ├── ntapi.rs      # NT API bindings
│   │   └── ghosting.rs   # Core implementation
│   ├── examples/         # Example code
│   ├── Cargo.toml        # Package manifest
│   └── README.md         # Documentation
└── README.md             # Root readme
```

---

## Pull Request Process

### Before Starting

1. **Create an issue** first to discuss major changes
2. **Fork the repository**
3. **Create a feature branch** from `main`
4. **Keep changes focused** - one feature/fix per PR

### Development Workflow

```bash
# Create a feature branch
git checkout -b feature/your-feature-name

# Make your changes
# ... edit files ...

# Format code
cargo fmt

# Check for issues
cargo clippy

# Run tests
cargo test

# Build examples
cargo build --examples

# Commit with clear messages
git commit -m "feat: add new feature"

# Push to your fork
git push origin feature/your-feature-name
```

### Submitting the PR

1. **Fill out the PR template** completely
2. **Link related issues** using keywords (Fixes #123)
3. **Add tests** for new functionality
4. **Update documentation** as needed
5. **Ensure CI passes** before requesting review

### PR Review Process

- Maintainers will review within **3-5 business days**
- Address feedback in new commits
- Once approved, maintainers will merge
- Your contribution will be credited

---

## Coding Standards

### Rust Style Guide

Follow the official [Rust Style Guide](https://doc.rust-lang.org/nightly/style-guide/).

**Key Points:**
- Use `cargo fmt` for formatting
- Run `cargo clippy` and fix all warnings
- Use meaningful variable and function names
- Add doc comments for public APIs
- Keep functions focused and small

### Code Organization

```rust
// 1. Imports
use std::fs;
use process_ghosting::GhostingBuilder;

// 2. Constants
const MAX_SIZE: usize = 1024;

// 3. Types/Structs
pub struct MyStruct {
    field: String,
}

// 4. Implementations
impl MyStruct {
    pub fn new() -> Self {
        // ...
    }
}

// 5. Functions
pub fn my_function() {
    // ...
}
```

### Documentation

All public APIs must have documentation:

```rust
/// Brief description of the function
///
/// More detailed explanation if needed.
///
/// # Arguments
///
/// * `arg1` - Description of arg1
/// * `arg2` - Description of arg2
///
/// # Returns
///
/// Description of return value
///
/// # Errors
///
/// When this function returns an error
///
/// # Examples
///
/// ```
/// use process_ghosting::my_function;
///
/// let result = my_function(arg1, arg2);
/// ```
pub fn my_function(arg1: &str, arg2: usize) -> Result<(), String> {
    // implementation
}
```

### Error Handling

- Use `Result<T, String>` for operations that can fail
- Provide descriptive error messages
- Don't panic in library code (except for truly unrecoverable errors)

```rust
// Good
if payload.is_empty() {
    return Err("Payload cannot be empty".to_string());
}

// Avoid
assert!(!payload.is_empty(), "Payload empty!"); // Don't panic
```

### Safety

- Minimize use of `unsafe` code
- Document all `unsafe` blocks with safety comments
- Ensure memory safety around FFI calls

```rust
unsafe {
    // SAFETY: ptr is guaranteed to be valid because...
    std::ptr::write(ptr, value);
}
```

---

## Commit Guidelines

### Commit Message Format

Use conventional commits format:

```
type(scope): subject

body (optional)

footer (optional)
```

### Types

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting)
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `test`: Adding or updating tests
- `build`: Build system changes
- `ci`: CI configuration changes
- `chore`: Other changes (dependencies, etc.)

### Examples

```bash
# Good commit messages
feat(api): add support for ARM64 architecture
fix(ghosting): handle empty payload error correctly
docs(readme): update installation instructions
test(builder): add tests for hex parsing

# Bad commit messages (avoid these)
fix bug
update stuff
WIP
asdfasdf
```

### Commit Best Practices

- Keep commits atomic (one logical change per commit)
- Write clear, descriptive messages
- Reference issues in commit messages
- Use present tense ("add feature" not "added feature")

---

## Testing

### Running Tests

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_name

# Run with output
cargo test -- --nocapture

# Run with backtrace
RUST_BACKTRACE=1 cargo test
```

### Writing Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feature() {
        let result = my_function();
        assert!(result.is_ok());
    }

    #[test]
    fn test_error_case() {
        let result = my_function_with_error();
        assert!(result.is_err());
    }
}
```

### Test Requirements

- Add tests for new features
- Update tests when changing behavior
- Aim for good test coverage
- Test both success and failure cases
- Test edge cases and boundary conditions

---

## Documentation

### Documentation Types

1. **API Documentation** (in code)
   - Use `///` for doc comments
   - Include examples in doc tests
   - Document all public items

2. **README**
   - Keep up-to-date with features
   - Include clear examples
   - Update installation instructions

3. **Examples**
   - Provide working code samples
   - Include comments explaining steps
   - Keep examples simple and focused

4. **CHANGELOG**
   - Document all changes
   - Follow Keep a Changelog format
   - Update with each release

### Building Documentation

```bash
# Build and open docs
cargo doc --open

# Check for doc warnings
cargo doc --no-deps 2>&1 | grep warning
```

---

## Getting Help

- **Questions?** Open a GitHub Discussion
- **Found a bug?** Create an issue
- **Need clarification?** Comment on relevant issues/PRs
- **Want to chat?** Reach out to maintainers

---

## Recognition

Contributors will be:
- Listed in CHANGELOG.md
- Mentioned in release notes
- Added to GitHub contributors list

---

## Legal and Ethical Guidelines

**Important**: This project is for educational and authorized security research only.

By contributing, you agree:
- ✅ Your contributions are for legal purposes
- ✅ You will not add features that facilitate malicious use
- ✅ You have the right to submit your code
- ✅ Your code is licensed under MIT
- ✅ You follow responsible disclosure for security issues

**Prohibited Contributions:**
- ❌ Features designed for malicious use
- ❌ Code that enables unauthorized access
- ❌ Bypassing security without disclosure
- ❌ Anything illegal or unethical

---

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to ProcessGhosting! 🙏

**Questions?** Feel free to ask in issues or discussions.

**BlackTechX**