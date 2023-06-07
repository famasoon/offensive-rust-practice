use winapi::ctypes::*;
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory};
use winapi::um::processthreadsapi::{CreateRemoteThread, OpenProcess};

pub fn DllInject(proc_handle: *mut c_void, dll_path: &str) {
    unsafe {
        let remote_base = VirtualAllocEx(
            proc_handle,
            std::ptr::null_mut(),
            dll_path.len(),
            0x1000,
            0x40,
        );
        WriteProcessMemory(
            proc_handle,
            remote_base,
            dll_path.as_bytes().as_ptr() as *const c_void,
            dll_path.len(),
            std::ptr::null_mut(),
        );
        let dll_handle = GetModuleHandleA("kernel32.dll\0".as_ptr() as *const i8);
        let func_address = GetProcAddress(dll_handle, "LoadLibraryA\0".as_ptr() as *const i8);

        CreateRemoteThread(
            proc_handle,
            std::ptr::null_mut(),
            0,
            Some(std::mem::transmute(func_address)),
            remote_base,
            0,
            std::ptr::null_mut(),
        );
    }
}

fn main() {
    let pid: u32 = 100; // modify real process ID
    let dll_path = r#"injectDLL"#; // modify real DLL
    unsafe{
        let proc_handle = OpenProcess(0x001FFFFF, 0, pid);
        DllInject(proc_handle, dll_path);
    }
}
