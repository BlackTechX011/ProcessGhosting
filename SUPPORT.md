# Support

Looking for help with ProcessGhosting? You're in the right place!

## 📚 Documentation

Start with our comprehensive documentation:

- **[README.md](README.md)** - Overview and quick start guide
- **[API Documentation](https://docs.rs/processghosting)** - Complete API reference
- **[Examples](examples/)** - Working code samples
- **[CHANGELOG.md](CHANGELOG.md)** - Version history and changes

## 🔍 Before Asking for Help

Please check these resources first:

1. **Read the documentation** - Most questions are answered there
2. **Search existing issues** - Your question might already be answered
3. **Check discussions** - Browse previous Q&A threads
4. **Try the examples** - Run the example code to understand usage

## 💬 Getting Help

### GitHub Discussions (Recommended)

For questions and general discussion:

👉 **[Start a Discussion](https://github.com/BlackTechX011/ProcessGhosting-rs/discussions)**

**Categories:**
- **Q&A** - Ask questions and get help
- **Ideas** - Share and discuss feature ideas
- **Show and Tell** - Share what you've built
- **General** - General discussion

**When to use Discussions:**
- ❓ How do I...?
- 💡 Feature ideas and suggestions
- 🎯 Best practices questions
- 📖 Documentation clarifications
- 🤝 Community help

### GitHub Issues

For bugs and specific problems:

👉 **[Report a Bug](https://github.com/BlackTechX011/ProcessGhosting-rs/issues/new/choose)**

**When to use Issues:**
- 🐛 You found a bug
- 📝 Documentation is wrong or missing
- 💥 Something crashes or errors
- 🔒 Security concerns (use private advisory)

**Issue Templates:**
- Bug Report
- Feature Request
- Documentation Issue
- Security Vulnerability (private)

## 🆘 Common Issues

### Installation Problems

**Problem**: Can't install or build

**Solutions**:
```bash
# Update Rust
rustup update

# Clean and rebuild
cargo clean
cargo build

# Check Rust version
rustc --version  # Should be 1.70.0 or later
```

### Windows-Only

**Problem**: This only works on Windows

**Solution**: ProcessGhosting uses Windows NT APIs and can only run on Windows. Linux/macOS are not supported.

### Architecture Issues

**Problem**: Payload doesn't execute

**Solutions**:
- Ensure payload architecture matches builder configuration
- Use `.x64()` for 64-bit payloads
- Use `.x86()` for 32-bit payloads
- Verify PE file is valid: `dumpbin /headers payload.exe`

### Permission Errors

**Problem**: Access denied or permission errors

**Solutions**:
- Run as Administrator (if needed)
- Check antivirus/EDR settings
- Verify file permissions
- Ensure authorized testing environment

## 📖 Learning Resources

### Beginner

Start here if you're new:
1. Read the [README.md](README.md)
2. Run `basic_usage` example
3. Try the `from_file` example
4. Explore other examples

### Intermediate

Once you're comfortable:
1. Study the `full_demo` example
2. Read the API documentation
3. Experiment with different configurations
4. Try the hex conversion utilities

### Advanced

For advanced usage:
1. Read the source code in `src/`
2. Understand NT API calls
3. Review the original research paper
4. Contribute to the project

## 🔒 Security Issues

**DO NOT** report security vulnerabilities in public issues!

### For vulnerabilities IN ProcessGhosting:

1. **Use GitHub Security Advisories**:
   - Go to Security tab → "Report a vulnerability"
   - Or: https://github.com/BlackTechX011/ProcessGhosting-rs/security/advisories/new

2. **What to include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Impact assessment
   - Suggested fix (if any)

### For reporting illegal use:

If you discover someone using this tool illegally:
1. Contact repository maintainers privately
2. Report to appropriate authorities if serious
3. Do NOT engage with the individual

See [SECURITY.md](SECURITY.md) for full details.

## 💼 Commercial Support

Currently, no commercial support is offered. This is an open-source project maintained by the community.

For organizations needing support:
- Consider hiring a security consultant familiar with the project
- Contribute to the project to help improve it
- Sponsor development through GitHub Sponsors

## 🤝 Contributing

Want to help improve ProcessGhosting?

- **Report bugs** - Help us fix issues
- **Suggest features** - Share your ideas
- **Improve docs** - Fix typos or add examples
- **Submit code** - Contribute improvements

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📧 Contact

### Public Communication (Preferred)

- **Discussions**: For questions and ideas
- **Issues**: For bugs and problems
- **Pull Requests**: For code contributions

### Private Communication

For sensitive matters only:
- **Security issues**: Use GitHub Security Advisories
- **Other private matters**: Contact maintainers through GitHub

**Please use public channels when possible** - it helps everyone!

## 🌍 Community

Join our community:

- **GitHub Discussions** - Ask and answer questions
- **GitHub Issues** - Report bugs and request features
- **Pull Requests** - Contribute code

## ⏰ Response Times

We're a small team, so please be patient:

- **Discussions**: Usually within 1-3 days
- **Issues**: Usually within 3-5 days
- **Pull Requests**: Usually within 5-7 days
- **Security issues**: As soon as possible

**Note**: Response times may vary. We're volunteers!

## ❓ FAQ

### Can I use this in production?

Use at your own risk. This is a security research tool. Ensure you have proper authorization and comply with all laws.

### Is this malware?

No. ProcessGhosting is a security research tool for educational purposes and authorized testing. Misuse is prohibited.

### Why Windows only?

ProcessGhosting uses Windows NT APIs that don't exist on other platforms.

### Can you help me hack/bypass [system]?

No. We don't assist with unauthorized access or illegal activities.

### Will you add feature X?

Maybe! Open a discussion or feature request to start the conversation.

### How do I contribute?

See [CONTRIBUTING.md](CONTRIBUTING.md) for complete guidelines.

### Where's the chat/Discord/Slack?

We currently use GitHub Discussions for all community interaction.

## 📋 Checklist: Before Asking

Before posting, please confirm:

- [ ] I read the documentation
- [ ] I searched existing issues
- [ ] I checked discussions
- [ ] I tried the examples
- [ ] I'm using the latest version
- [ ] I'm on Windows
- [ ] This is for legal, authorized use

## 🙏 Thank You

Thanks for using ProcessGhosting and being part of our community!

---

**Remember**: Use this tool responsibly and legally. Happy hacking! 🔒👻

**BlackTechX**