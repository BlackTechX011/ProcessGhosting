# Pull Request

## Description

<!-- Provide a clear and concise description of your changes -->

Fixes #(issue)

## Type of Change

<!-- Mark with an 'x' the type(s) that apply -->

- [ ] 🐛 Bug fix (non-breaking change which fixes an issue)
- [ ] ✨ New feature (non-breaking change which adds functionality)
- [ ] 💥 Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] 📝 Documentation update
- [ ] 🎨 Code style update (formatting, renaming)
- [ ] ♻️ Code refactoring (no functional changes)
- [ ] ⚡ Performance improvement
- [ ] ✅ Test update
- [ ] 🔧 Build configuration change
- [ ] 🔒 Security fix

## Changes Made

<!-- List the main changes in bullet points -->

- 
- 
- 

## Testing

<!-- Describe how you tested your changes -->

### Test Environment
- **OS**: Windows 10/11/Server
- **Architecture**: x64 / x86
- **Rust Version**: 
- **Cargo Version**: 

### Test Cases
<!-- Describe what you tested -->

- [ ] Tested with x64 payloads
- [ ] Tested with x86 payloads
- [ ] Tested all examples
- [ ] Added new tests
- [ ] All existing tests pass

### Test Commands
```bash
# Commands used for testing
cargo test
cargo clippy
cargo fmt --check
cargo build --examples
```

## Checklist

<!-- Mark items with an 'x' as you complete them -->

### Code Quality
- [ ] My code follows the Rust style guidelines
- [ ] I have performed a self-review of my code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] My code builds without warnings
- [ ] `cargo clippy` passes without warnings
- [ ] `cargo fmt` has been run

### Documentation
- [ ] I have updated the documentation (README, docs, comments)
- [ ] I have added/updated examples if needed
- [ ] I have updated CHANGELOG.md
- [ ] My changes generate no new warnings in `cargo doc`

### Testing
- [ ] I have added tests that prove my fix/feature works
- [ ] New and existing unit tests pass locally
- [ ] I have tested on both x64 and x86 (if applicable)

### Security
- [ ] I have considered security implications of my changes
- [ ] My changes do not introduce new security vulnerabilities
- [ ] I am using this for authorized security research only

### Dependencies
- [ ] I have not added unnecessary dependencies
- [ ] If I added dependencies, I have justified them in this PR

## Breaking Changes

<!-- If this is a breaking change, describe what breaks and how to migrate -->

**Does this PR introduce breaking changes?** Yes / No

If yes, describe:
- What breaks:
- Migration path:
- Deprecated APIs:

## Screenshots / Code Examples

<!-- If applicable, add screenshots or code examples -->

### Before
```rust
// Old code example
```

### After
```rust
// New code example
```

## Performance Impact

<!-- Describe any performance implications -->

- [ ] No performance impact
- [ ] Performance improved
- [ ] Performance may be affected (explain below)

**Details:**

## Additional Notes

<!-- Any additional information for reviewers -->

## Related Issues/PRs

<!-- Link related issues or pull requests -->

- Related to #
- Closes #
- Depends on #

---

## Reviewer Notes

<!-- For reviewers: Add any specific areas you want feedback on -->

**Areas for special attention:**
- 
- 

**Questions for reviewers:**
- 
- 

---

**By submitting this PR, I confirm:**
- [ ] My code is for legal and authorized security research purposes
- [ ] I have read and agree to the project's Code of Conduct
- [ ] I have the right to submit this code under the MIT license