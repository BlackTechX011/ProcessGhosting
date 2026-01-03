//! NT API Definitions and Types for ProcessGhosting Library
//! Author: BlackTechX

#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]

use winapi::shared::basetsd::{SIZE_T, PSIZE_T, ULONG_PTR};
use winapi::shared::minwindef::{BOOL, BYTE, DWORD, ULONG, USHORT, PULONG, LPVOID};
use winapi::shared::ntdef::{HANDLE, NTSTATUS, PVOID, LARGE_INTEGER, PLARGE_INTEGER, BOOLEAN};
use winapi::um::winnt::{ACCESS_MASK, PIMAGE_NT_HEADERS};

// ============================================================================
// Constants
// ============================================================================

pub const STATUS_SUCCESS: NTSTATUS = 0;
pub const STATUS_IMAGE_NOT_AT_BASE: NTSTATUS = 0x40000003;
pub const OBJ_CASE_INSENSITIVE: ULONG = 0x00000040;
pub const FILE_SUPERSEDED: ULONG = 0x00000000;
pub const FILE_SYNCHRONOUS_IO_NONALERT: ULONG = 0x00000020;
pub const RTL_USER_PROC_PARAMS_NORMALIZED: ULONG = 0x00000001;
pub const PS_INHERIT_HANDLES: ULONG = 4;
pub const RTL_MAX_DRIVE_LETTERS: usize = 32;

// ============================================================================
// Structures
// ============================================================================

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UNICODE_STRING {
    pub Length: USHORT,
    pub MaximumLength: USHORT,
    pub Buffer: *mut u16,
}

impl Default for UNICODE_STRING {
    fn default() -> Self {
        Self {
            Length: 0,
            MaximumLength: 0,
            Buffer: std::ptr::null_mut(),
        }
    }
}

#[repr(C)]
pub struct OBJECT_ATTRIBUTES {
    pub Length: ULONG,
    pub RootDirectory: HANDLE,
    pub ObjectName: *mut UNICODE_STRING,
    pub Attributes: ULONG,
    pub SecurityDescriptor: PVOID,
    pub SecurityQualityOfService: PVOID,
}

impl OBJECT_ATTRIBUTES {
    pub fn new(object_name: *mut UNICODE_STRING, attributes: ULONG) -> Self {
        Self {
            Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as ULONG,
            RootDirectory: std::ptr::null_mut(),
            ObjectName: object_name,
            Attributes: attributes,
            SecurityDescriptor: std::ptr::null_mut(),
            SecurityQualityOfService: std::ptr::null_mut(),
        }
    }
}

#[repr(C)]
pub struct IO_STATUS_BLOCK {
    pub Status: NTSTATUS,
    pub Information: ULONG_PTR,
}

impl Default for IO_STATUS_BLOCK {
    fn default() -> Self {
        Self {
            Status: 0,
            Information: 0,
        }
    }
}

#[repr(C)]
pub struct FILE_DISPOSITION_INFORMATION {
    pub DeleteFile: BOOLEAN,
}

#[repr(C)]
pub struct CLIENT_ID {
    pub UniqueProcess: HANDLE,
    pub UniqueThread: HANDLE,
}

#[repr(C)]
pub struct CURDIR {
    pub DosPath: UNICODE_STRING,
    pub Handle: HANDLE,
}

#[repr(C)]
pub struct RTL_DRIVE_LETTER_CURDIR {
    pub Flags: USHORT,
    pub Length: USHORT,
    pub TimeStamp: ULONG,
    pub DosPath: UNICODE_STRING,
}

#[repr(C)]
pub struct RTL_USER_PROCESS_PARAMETERS {
    pub MaximumLength: ULONG,
    pub Length: ULONG,
    pub Flags: ULONG,
    pub DebugFlags: ULONG,
    pub ConsoleHandle: HANDLE,
    pub ConsoleFlags: ULONG,
    pub StandardInput: HANDLE,
    pub StandardOutput: HANDLE,
    pub StandardError: HANDLE,
    pub CurrentDirectory: CURDIR,
    pub DllPath: UNICODE_STRING,
    pub ImagePathName: UNICODE_STRING,
    pub CommandLine: UNICODE_STRING,
    pub Environment: PVOID,
    pub StartingX: ULONG,
    pub StartingY: ULONG,
    pub CountX: ULONG,
    pub CountY: ULONG,
    pub CountCharsX: ULONG,
    pub CountCharsY: ULONG,
    pub FillAttribute: ULONG,
    pub WindowFlags: ULONG,
    pub ShowWindowFlags: ULONG,
    pub WindowTitle: UNICODE_STRING,
    pub DesktopInfo: UNICODE_STRING,
    pub ShellInfo: UNICODE_STRING,
    pub RuntimeData: UNICODE_STRING,
    pub CurrentDirectories: [RTL_DRIVE_LETTER_CURDIR; RTL_MAX_DRIVE_LETTERS],
    pub EnvironmentSize: ULONG_PTR,
    pub EnvironmentVersion: ULONG_PTR,
    pub PackageDependencyData: PVOID,
    pub ProcessGroupId: ULONG,
}

#[repr(C)]
pub struct PEB_LDR_DATA {
    pub Reserved1: [BYTE; 8],
    pub Reserved2: [PVOID; 3],
    pub InMemoryOrderModuleList: LIST_ENTRY,
}

#[repr(C)]
pub struct LIST_ENTRY {
    pub Flink: *mut LIST_ENTRY,
    pub Blink: *mut LIST_ENTRY,
}

#[repr(C)]
pub struct PEB_FREE_BLOCK {
    pub Next: *mut PEB_FREE_BLOCK,
    pub Size: ULONG,
}

pub type PPEBLOCKROUTINE = Option<unsafe extern "system" fn(PebLock: PVOID)>;
pub type PPS_POST_PROCESS_INIT_ROUTINE = Option<unsafe extern "system" fn()>;

#[repr(C)]
pub struct PEB {
    pub InheritedAddressSpace: BOOLEAN,
    pub ReadImageFileExecOptions: BOOLEAN,
    pub BeingDebugged: BOOLEAN,
    pub Spare: BOOLEAN,
    pub Mutant: HANDLE,
    pub ImageBaseAddress: PVOID,
    pub LoaderData: *mut PEB_LDR_DATA,
    pub ProcessParameters: *mut RTL_USER_PROCESS_PARAMETERS,
    pub SubSystemData: PVOID,
    pub ProcessHeap: PVOID,
    pub FastPebLock: PVOID,
    pub FastPebLockRoutine: PPEBLOCKROUTINE,
    pub FastPebUnlockRoutine: PPEBLOCKROUTINE,
    pub EnvironmentUpdateCount: ULONG,
    pub KernelCallbackTable: *mut PVOID,
    pub EventLogSection: PVOID,
    pub EventLog: PVOID,
    pub FreeList: *mut PEB_FREE_BLOCK,
    pub TlsExpansionCounter: ULONG,
    pub TlsBitmap: PVOID,
    pub TlsBitmapBits: [ULONG; 2],
    pub ReadOnlySharedMemoryBase: PVOID,
    pub ReadOnlySharedMemoryHeap: PVOID,
    pub ReadOnlyStaticServerData: *mut PVOID,
    pub AnsiCodePageData: PVOID,
    pub OemCodePageData: PVOID,
    pub UnicodeCaseTableData: PVOID,
    pub NumberOfProcessors: ULONG,
    pub NtGlobalFlag: ULONG,
    pub Spare2: [BYTE; 4],
    pub CriticalSectionTimeout: LARGE_INTEGER,
    pub HeapSegmentReserve: ULONG,
    pub HeapSegmentCommit: ULONG,
    pub HeapDeCommitTotalFreeThreshold: ULONG,
    pub HeapDeCommitFreeBlockThreshold: ULONG,
    pub NumberOfHeaps: ULONG,
    pub MaximumNumberOfHeaps: ULONG,
    pub ProcessHeaps: *mut *mut PVOID,
    pub GdiSharedHandleTable: PVOID,
    pub ProcessStarterHelper: PVOID,
    pub GdiDCAttributeList: PVOID,
    pub LoaderLock: PVOID,
    pub OSMajorVersion: ULONG,
    pub OSMinorVersion: ULONG,
    pub OSBuildNumber: ULONG,
    pub OSPlatformId: ULONG,
    pub ImageSubSystem: ULONG,
    pub ImageSubSystemMajorVersion: ULONG,
    pub ImageSubSystemMinorVersion: ULONG,
    pub GdiHandleBuffer: [ULONG; 0x22],
    pub PostProcessInitRoutine: ULONG,
    pub TlsExpansionBitmap: ULONG,
    pub TlsExpansionBitmapBits: [BYTE; 0x80],
    pub SessionId: ULONG,
}

#[repr(C)]
pub struct PROCESS_BASIC_INFORMATION {
    pub Reserved1: PVOID,
    pub PebBaseAddress: *mut PEB,
    pub Reserved2: [PVOID; 2],
    pub UniqueProcessId: ULONG_PTR,
    pub Reserved3: PVOID,
}

impl Default for PROCESS_BASIC_INFORMATION {
    fn default() -> Self {
        Self {
            Reserved1: std::ptr::null_mut(),
            PebBaseAddress: std::ptr::null_mut(),
            Reserved2: [std::ptr::null_mut(); 2],
            UniqueProcessId: 0,
            Reserved3: std::ptr::null_mut(),
        }
    }
}

// ============================================================================
// Enums
// ============================================================================

#[repr(C)]
pub enum PROCESSINFOCLASS {
    ProcessBasicInformation = 0,
    ProcessDebugPort = 7,
    ProcessWow64Information = 26,
    ProcessImageFileName = 27,
    ProcessBreakOnTermination = 29,
}

#[repr(C)]
pub enum SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2,
}

#[repr(C)]
pub enum FILE_INFORMATION_CLASS {
    FileDirectoryInformation = 1,
    FileBasicInformation = 4,
    FileStandardInformation = 5,
    FileDispositionInformation = 13,
}

// ============================================================================
// Function Type Definitions
// ============================================================================

pub type FnNtOpenFile = unsafe extern "system" fn(
    FileHandle: *mut HANDLE,
    DesiredAccess: ACCESS_MASK,
    ObjectAttributes: *mut OBJECT_ATTRIBUTES,
    IoStatusBlock: *mut IO_STATUS_BLOCK,
    ShareAccess: ULONG,
    OpenOptions: ULONG,
) -> NTSTATUS;

pub type FnNtSetInformationFile = unsafe extern "system" fn(
    FileHandle: HANDLE,
    IoStatusBlock: *mut IO_STATUS_BLOCK,
    FileInformation: PVOID,
    Length: ULONG,
    FileInformationClass: FILE_INFORMATION_CLASS,
) -> NTSTATUS;

pub type FnNtCreateSection = unsafe extern "system" fn(
    SectionHandle: *mut HANDLE,
    DesiredAccess: ACCESS_MASK,
    ObjectAttributes: *mut OBJECT_ATTRIBUTES,
    MaximumSize: PLARGE_INTEGER,
    SectionPageProtection: ULONG,
    AllocationAttributes: ULONG,
    FileHandle: HANDLE,
) -> NTSTATUS;

pub type FnNtCreateProcessEx = unsafe extern "system" fn(
    ProcessHandle: *mut HANDLE,
    DesiredAccess: ACCESS_MASK,
    ObjectAttributes: *mut OBJECT_ATTRIBUTES,
    ParentProcess: HANDLE,
    Flags: ULONG,
    SectionHandle: HANDLE,
    DebugPort: HANDLE,
    ExceptionPort: HANDLE,
    InJob: BOOLEAN,
) -> NTSTATUS;

pub type FnNtQueryInformationProcess = unsafe extern "system" fn(
    ProcessHandle: HANDLE,
    ProcessInformationClass: PROCESSINFOCLASS,
    ProcessInformation: PVOID,
    ProcessInformationLength: ULONG,
    ReturnLength: PULONG,
) -> NTSTATUS;

pub type FnNtReadVirtualMemory = unsafe extern "system" fn(
    ProcessHandle: HANDLE,
    BaseAddress: PVOID,
    Buffer: PVOID,
    BufferSize: SIZE_T,
    NumberOfBytesRead: PSIZE_T,
) -> NTSTATUS;

pub type FnNtWriteVirtualMemory = unsafe extern "system" fn(
    ProcessHandle: HANDLE,
    BaseAddress: PVOID,
    Buffer: PVOID,
    BufferSize: SIZE_T,
    NumberOfBytesWritten: PSIZE_T,
) -> NTSTATUS;

pub type FnNtAllocateVirtualMemory = unsafe extern "system" fn(
    ProcessHandle: HANDLE,
    BaseAddress: *mut PVOID,
    ZeroBits: ULONG_PTR,
    RegionSize: PSIZE_T,
    AllocationType: ULONG,
    Protect: ULONG,
) -> NTSTATUS;

pub type FnNtCreateThreadEx = unsafe extern "system" fn(
    ThreadHandle: *mut HANDLE,
    DesiredAccess: ACCESS_MASK,
    ObjectAttributes: LPVOID,
    ProcessHandle: HANDLE,
    StartAddress: LPVOID,
    Parameter: LPVOID,
    CreateSuspended: BOOL,
    StackZeroBits: DWORD,
    SizeOfStackCommit: DWORD,
    SizeOfStackReserve: DWORD,
    BytesBuffer: LPVOID,
) -> NTSTATUS;

pub type FnRtlInitUnicodeString = unsafe extern "system" fn(
    DestinationString: *mut UNICODE_STRING,
    SourceString: *const u16,
);

pub type FnRtlImageNtHeader = unsafe extern "system" fn(
    Base: PVOID,
) -> PIMAGE_NT_HEADERS;

pub type FnRtlCreateProcessParametersEx = unsafe extern "system" fn(
    pProcessParameters: *mut *mut RTL_USER_PROCESS_PARAMETERS,
    ImagePathName: *mut UNICODE_STRING,
    DllPath: *mut UNICODE_STRING,
    CurrentDirectory: *mut UNICODE_STRING,
    CommandLine: *mut UNICODE_STRING,
    Environment: PVOID,
    WindowTitle: *mut UNICODE_STRING,
    DesktopInfo: *mut UNICODE_STRING,
    ShellInfo: *mut UNICODE_STRING,
    RuntimeData: *mut UNICODE_STRING,
    Flags: ULONG,
) -> NTSTATUS;

// ============================================================================
// Helper Functions
// ============================================================================

#[inline]
pub fn nt_success(status: NTSTATUS) -> bool {
    status >= 0
}

pub unsafe fn get_ntdll_function<T>(name: &str) -> Result<T, String> {
    use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
    use std::ffi::CString;

    let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr() as *const i8);
    if ntdll.is_null() {
        return Err("[-] Failed to get ntdll.dll handle".to_string());
    }

    let func_name = CString::new(name).map_err(|_| "[-] Invalid function name")?;
    let func = GetProcAddress(ntdll, func_name.as_ptr());
    
    if func.is_null() {
        return Err(format!("[-] Failed to locate {} API", name));
    }

    Ok(std::mem::transmute_copy(&func))
}