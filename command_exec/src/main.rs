use std::env;
use std::process::Command;

fn execute_cmd(cmd: &str) -> String {
    let temp = "/c".to_owned();
    let full_cmd = temp + cmd;

    let spaced_cmd: Vec<&str> = full_cmd.split(" ").collect();
    let res = Command::new("cmd.exe").args(&spaced_cmd).output().unwrap();

    let stdout = String::from_utf8_lossy(res.stdout.as_slice());
    let stderr = String::from_utf8_lossy(res.stderr.as_slice());

    if stdout.len() > 0 {
        stdout.to_string()
    } else {
        stderr.to_string()
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        println!("Usage: {} command", args[0]);
    }

    let res = execute_cmd(&args[1]);
    print!("{}", res)
}
