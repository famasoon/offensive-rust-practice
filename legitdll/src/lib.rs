use winapi::um::winuser::MessageBoxA;

#[no_mangle]
pub unsafe extern "C" fn legit_function() {
    MessageBoxA(
        std::ptr::null_mut(),
        "This is from legit dll\0".as_ptr() as *const i8,
        "Title of the box\0".as_ptr() as *const i8,
        0,
    );
}
