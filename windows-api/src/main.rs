
use winapi::um::winuser::*;

fn main() {
    let text = "hello world\0";
    let title = "title\0";
    unsafe {
        MessageBoxA(
            std::ptr::null_mut(),
            text.as_bytes().as_ptr() as *const i8,
            title.as_bytes().as_ptr() as *const i8,
            0,
        );
    }
    
}
