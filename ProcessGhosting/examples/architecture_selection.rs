//! Select between x86 and x64 architecture
//! Author: BlackTechX

use process_ghosting::{GhostingBuilder, Architecture, init};
use std::env;

fn main() {
    init();

    println!("[*] Architecture Selection Example\n");

    let args: Vec<String> = env::args().collect();
    
    // Parse arguments
    let (file_path, arch) = if args.len() >= 3 {
        let arch = match args[2].to_lowercase().as_str() {
            "x86" | "32" | "i386" => Architecture::X86,
            "x64" | "64" | "amd64" => Architecture::X64,
            _ => {
                eprintln!("[-] Unknown architecture: {}", args[2]);
                eprintln!("    Use: x86, x64, 32, or 64");
                return;
            }
        };
        (args[1].as_str(), arch)
    } else if args.len() == 2 {
        (args[1].as_str(), Architecture::X64) // Default to x64
    } else {
        println!("Usage: {} <payload.exe> [arch]", args[0]);
        println!();
        println!("Architectures:");
        println!("  x86, 32, i386   - 32-bit");
        println!("  x64, 64, amd64  - 64-bit (default)");
        return;
    };

    println!("[*] File: {}", file_path);
    println!("[*] Architecture: {}", arch);
    println!();

    match GhostingBuilder::from_file(file_path) {
        Ok(builder) => {
            let result = builder
                .architecture(arch)
                .with_logging()
                .execute();

            match result {
                Ok(_) => println!("\n[+] Success!"),
                Err(e) => eprintln!("\n[-] Failed: {}", e),
            }
        }
        Err(e) => eprintln!("[-] Error: {}", e),
    }
}