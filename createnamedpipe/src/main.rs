use std::ptr::null_mut;
use winapi::um::fileapi::WriteFile;
use winapi::um::winbase::CreateNamedPipeA;
use winapi::um::winbase::{PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE};
use winapi::um::winnt::{HANDLE, LPCSTR};

fn main() {
    let pipe_name: LPCSTR = "\\\\.\\pipe\\mypipe".as_ptr() as *const i8;
    let mut bytes_write: u32 = 0;
    let message = "Rust is Good for offsec";
    let server_pipe: HANDLE = unsafe {
        CreateNamedPipeA(
            pipe_name,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE,
            1,
            2048,
            2048,
            0,
            null_mut(),
        )
    };
    println!("Sending message to Pipe");

    unsafe {
        WriteFile(
            server_pipe,
            message.as_ptr() as *const winapi::ctypes::c_void,
            message.len() as u32,
            &mut bytes_write,
            null_mut(),
        );
    }
}
