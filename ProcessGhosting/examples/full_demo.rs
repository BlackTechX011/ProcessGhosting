//! Full demonstration of all library features
//! Author: BlackTechX

use process_ghosting::{
    init, GhostingBuilder, Architecture,
    exe_to_hex_string, exe_to_hex_array, print_exe_hex,
    parse_hex_string, bytes_to_hex_string, read_exe_bytes,
    ghost_payload, ghost_payload_file, ghost_payload_hex,
};
use std::env;

fn main() {
    // ========================================
    // INITIALIZATION
    // ========================================
    init();
    
    println!("╔════════════════════════════════════════════╗");
    println!("║     ProcessGhosting Full Demo              ║");
    println!("║     By BlackTechX                          ║");
    println!("╚════════════════════════════════════════════╝\n");

    let args: Vec<String> = env::args().collect();
    let test_file = if args.len() > 1 { &args[1] } else { "C:\\Windows\\System32\\notepad.exe" };

    // ========================================
    // SECTION 1: HEX UTILITIES
    // ========================================
    println!("┌────────────────────────────────────────────┐");
    println!("│ Section 1: Hex Utilities                   │");
    println!("└────────────────────────────────────────────┘\n");

    // 1.1 Parse different hex formats
    println!("[1.1] Parsing different hex formats:\n");
    
    let formats = [
        "4D5A9000",
        "4D 5A 90 00",
        "0x4D, 0x5A, 0x90, 0x00",
        "\\x4D\\x5A\\x90\\x00",
    ];

    for fmt in &formats {
        match parse_hex_string(fmt) {
            Ok(bytes) => println!("      '{}' -> {:02X?}", fmt, bytes),
            Err(e) => println!("      '{}' -> Error: {}", fmt, e),
        }
    }
    println!();

    // 1.2 Convert bytes to hex
    println!("[1.2] Converting bytes to hex string:");
    let sample_bytes = vec![0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00];
    let hex_string = bytes_to_hex_string(&sample_bytes);
    println!("      {:?} -> {}\n", sample_bytes, hex_string);

    // 1.3 Read file as hex (first 64 bytes)
    println!("[1.3] Reading file header as hex:");
    match read_exe_bytes(test_file) {
        Ok(bytes) => {
            let preview: Vec<u8> = bytes.iter().take(32).cloned().collect();
            println!("      File: {}", test_file);
            println!("      Size: {} bytes", bytes.len());
            println!("      First 32 bytes: {}", bytes_to_hex_string(&preview));
        }
        Err(e) => println!("      Error: {}", e),
    }
    println!();

    // ========================================
    // SECTION 2: BUILDER PATTERNS
    // ========================================
    println!("┌────────────────────────────────────────────┐");
    println!("│ Section 2: Builder Patterns                │");
    println!("└────────────────────────────────────────────┘\n");

    // 2.1 From raw bytes
    println!("[2.1] Builder from raw bytes:");
    let sample = vec![0x4D, 0x5A];
    let config = GhostingBuilder::new(&sample)
        .x64()
        .with_logging()
        .build();
    println!("      Payload size: {} bytes", config.payload.len());
    println!("      Architecture: {}", config.architecture);
    println!("      Verbose: {}\n", config.verbose);

    // 2.2 From file
    println!("[2.2] Builder from file:");
    match GhostingBuilder::from_file(test_file) {
        Ok(builder) => {
            let config = builder.x64().build();
            println!("      Loaded: {} bytes\n", config.payload.len());
        }
        Err(e) => println!("      Error: {}\n", e),
    }

    // 2.3 From hex string
    println!("[2.3] Builder from hex string:");
    match GhostingBuilder::from_hex_string("0x4D, 0x5A, 0x90, 0x00") {
        Ok(builder) => {
            let config = builder.build();
            println!("      Parsed: {} bytes\n", config.payload.len());
        }
        Err(e) => println!("      Error: {}\n", e),
    }

    // 2.4 Architecture selection
    println!("[2.4] Architecture selection:");
    
    let x64_config = GhostingBuilder::new(&[0x4D, 0x5A])
        .x64()
        .build();
    println!("      .x64() -> {}", x64_config.architecture);

    let x86_config = GhostingBuilder::new(&[0x4D, 0x5A])
        .x86()
        .build();
    println!("      .x86() -> {}", x86_config.architecture);

    let arch_config = GhostingBuilder::new(&[0x4D, 0x5A])
        .architecture(Architecture::X64)
        .build();
    println!("      .architecture(X64) -> {}\n", arch_config.architecture);

    // 2.5 Verbose control
    println!("[2.5] Verbose control:");
    
    let verbose = GhostingBuilder::new(&[0x4D, 0x5A])
        .with_logging()
        .build();
    println!("      .with_logging() -> verbose: {}", verbose.verbose);

    let silent = GhostingBuilder::new(&[0x4D, 0x5A])
        .silent()
        .build();
    println!("      .silent() -> verbose: {}\n", silent.verbose);

    // ========================================
    // SECTION 3: QUICK FUNCTIONS
    // ========================================
    println!("┌────────────────────────────────────────────┐");
    println!("│ Section 3: Quick Functions                 │");
    println!("└────────────────────────────────────────────┘\n");

    println!("[3.1] Available quick functions:");
    println!("      ghost_payload(&bytes)      - Execute from bytes");
    println!("      ghost_payload_file(path)   - Execute from file");
    println!("      ghost_payload_hex(hex_str) - Execute from hex string\n");

    // ========================================
    // SECTION 4: EXECUTION (DISABLED BY DEFAULT)
    // ========================================
    println!("┌────────────────────────────────────────────┐");
    println!("│ Section 4: Execution Demo                  │");
    println!("└────────────────────────────────────────────┘\n");

    println!("[4.1] To execute process ghosting:");
    println!();
    println!("      // Method 1: Builder pattern");
    println!("      GhostingBuilder::from_file(\"payload.exe\")?");
    println!("          .x64()");
    println!("          .with_logging()");
    println!("          .execute()?;");
    println!();
    println!("      // Method 2: Quick function");
    println!("      ghost_payload_file(\"payload.exe\")?;");
    println!();
    println!("      // Method 3: From embedded bytes");
    println!("      const PAYLOAD: &[u8] = include_bytes!(\"payload.exe\");");
    println!("      ghost_payload(PAYLOAD)?;");
    println!();

    // Uncomment below to actually execute
    /*
    println!("[4.2] Executing ghosting...\n");
    
    match GhostingBuilder::from_file("your_payload.exe") {
        Ok(builder) => {
            match builder.x64().with_logging().execute() {
                Ok(_) => println!("\n[+] Ghosting successful!"),
                Err(e) => println!("\n[-] Ghosting failed: {}", e),
            }
        }
        Err(e) => println!("[-] Failed to load payload: {}", e),
    }
    */

    println!("┌────────────────────────────────────────────┐");
    println!("│ Demo Complete                              │");
    println!("└────────────────────────────────────────────┘\n");
}