//! Execute payload from hex string
//! Author: BlackTechX

use process_ghosting::{GhostingBuilder, parse_hex_string, init};

fn main() {
    init();

    println!("[*] From Hex String Example\n");

    // Example: Various hex formats supported
    let hex_formats = [
        ("Continuous", "4D5A90000300000004000000FFFF0000"),
        ("Spaced", "4D 5A 90 00 03 00 00 00"),
        ("C-style", "0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00"),
        ("Escaped", "\\x4D\\x5A\\x90\\x00\\x03\\x00"),
    ];

    println!("[*] Supported hex formats:\n");
    
    for (name, hex) in &hex_formats {
        match parse_hex_string(hex) {
            Ok(bytes) => {
                println!("    {}: {} -> {:02X?}", name, hex, &bytes[..bytes.len().min(4)]);
            }
            Err(e) => {
                println!("    {}: Error - {}", name, e);
            }
        }
    }

    println!();

    // For actual execution, you would use a complete PE file in hex
    // This is just a demonstration of the parsing
    
    let sample_hex = "0x4D, 0x5A, 0x90, 0x00"; // MZ header start
    
    match GhostingBuilder::from_hex_string(sample_hex) {
        Ok(builder) => {
            println!("[+] Successfully parsed hex string");
            println!("[*] Payload size: {} bytes", builder.build().payload.len());
            
            // Note: This would fail with just the header
            // In real usage, provide complete PE bytes
            // builder.x64().execute();
        }
        Err(e) => {
            eprintln!("[-] Failed to parse: {}", e);
        }
    }
}