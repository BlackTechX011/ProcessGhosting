//! Comprehensive error handling example
//! Author: BlackTechX

use process_ghosting::{GhostingBuilder, init, parse_hex_string};

fn main() {
    init();

    println!("[*] Error Handling Example\n");

    // Test 1: Invalid file
    println!("[Test 1] Loading non-existent file:");
    match GhostingBuilder::from_file("nonexistent.exe") {
        Ok(_) => println!("    Unexpected success"),
        Err(e) => println!("    Expected error: {}", e),
    }
    println!();

    // Test 2: Invalid hex string
    println!("[Test 2] Parsing invalid hex:");
    match parse_hex_string("ZZZZ") {
        Ok(_) => println!("    Unexpected success"),
        Err(e) => println!("    Expected error: {}", e),
    }
    println!();

    // Test 3: Invalid PE (not MZ header)
    println!("[Test 3] Executing invalid PE:");
    let invalid_pe = vec![0x00, 0x00, 0x00, 0x00]; // Not MZ
    match GhostingBuilder::new(&invalid_pe).x64().execute() {
        Ok(_) => println!("    Unexpected success"),
        Err(e) => println!("    Expected error: {}", e),
    }
    println!();

    // Test 4: Empty payload
    println!("[Test 4] Empty payload:");
    match GhostingBuilder::new(&[]).x64().execute() {
        Ok(_) => println!("    Unexpected success"),
        Err(e) => println!("    Expected error: {}", e),
    }
    println!();

    // Test 5: Truncated PE
    println!("[Test 5] Truncated PE (only MZ header):");
    let truncated_pe = vec![0x4D, 0x5A]; // Just MZ
    match GhostingBuilder::new(&truncated_pe).x64().execute() {
        Ok(_) => println!("    Unexpected success"),
        Err(e) => println!("    Expected error: {}", e),
    }
    println!();

    println!("[*] Error handling tests complete.");
}