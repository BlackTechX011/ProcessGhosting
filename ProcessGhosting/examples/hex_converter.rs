//! Convert EXE files to hex format for embedding
//! Author: BlackTechX

use process_ghosting::{
    init, print_exe_hex, exe_to_hex_string, exe_to_hex_array,
    bytes_to_hex_string,
};
use std::env;
use std::fs;

fn print_usage(program: &str) {
    println!("Usage: {} <command> <file>", program);
    println!();
    println!("Commands:");
    println!("  print    Print hex array to console (for embedding in code)");
    println!("  string   Output as single line hex string");
    println!("  array    Output as formatted array with line breaks");
    println!("  save     Save hex to .txt file");
    println!();
    println!("Examples:");
    println!("  {} print payload.exe", program);
    println!("  {} save payload.exe", program);
}

fn main() {
    init();

    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        print_usage(&args[0]);
        return;
    }

    let command = &args[1];
    let file_path = &args[2];

    // Check if file exists
    if !std::path::Path::new(file_path).exists() {
        eprintln!("[-] File not found: {}", file_path);
        return;
    }

    match command.as_str() {
        "print" => {
            println!("[*] Converting {} to Rust byte array:\n", file_path);
            if let Err(e) = print_exe_hex(file_path) {
                eprintln!("[-] Error: {}", e);
            }
        }

        "string" => {
            println!("[*] Converting {} to hex string:\n", file_path);
            match exe_to_hex_string(file_path) {
                Ok(hex) => println!("{}", hex),
                Err(e) => eprintln!("[-] Error: {}", e),
            }
        }

        "array" => {
            println!("[*] Converting {} to formatted array:\n", file_path);
            match exe_to_hex_array(file_path) {
                Ok(hex) => println!("{}", hex),
                Err(e) => eprintln!("[-] Error: {}", e),
            }
        }

        "save" => {
            let output_path = format!("{}.hex.txt", file_path);
            println!("[*] Converting {} and saving to {}", file_path, output_path);

            match fs::read(file_path) {
                Ok(bytes) => {
                    let hex = bytes_to_hex_string(&bytes);
                    let content = format!(
                        "// File: {}\n// Size: {} bytes\n\nconst PAYLOAD: &[u8] = &[\n    {}\n];\n",
                        file_path,
                        bytes.len(),
                        hex
                    );

                    match fs::write(&output_path, content) {
                        Ok(_) => println!("[+] Saved to {}", output_path),
                        Err(e) => eprintln!("[-] Failed to save: {}", e),
                    }
                }
                Err(e) => eprintln!("[-] Failed to read file: {}", e),
            }
        }

        _ => {
            eprintln!("[-] Unknown command: {}", command);
            println!();
            print_usage(&args[0]);
        }
    }
}