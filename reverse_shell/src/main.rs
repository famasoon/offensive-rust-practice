use std::net::{Ipv4Addr, Shutdown, SocketAddrV4, TcpListener, TcpStream};
use std::process::{exit, Command};
use std::io::{self, Write, BufReader, BufRead};

fn main() {
    let bind_ip = "127.0.0.1".parse::<Ipv4Addr>();
    let bind_port: u16 = 1234;
    let ip_address = match bind_ip {
        Ok(i) => i,
        Err(e) => {
            println!("{}", e);
            exit(0);
        }
    };

    let socket_address = SocketAddrV4::new(ip_address, bind_port);
    let listn = TcpListener::bind(socket_address);
    let listner = match listn {
        Ok(l) => l,
        Err(e) => {
            println!("{}", e);
            exit(0)
        }
    };

    
    let (mut client_socket, client_address) = listner.accept().unwrap();
    println!("Client connected from: {}", client_address);

    loop {
        println!("Enter command to send: ");
        let mut input = String::new();
        io::stdin().read_line(&mut input).expect("String expect");
        input.push('\0');

        if input.as_str() == "quit" {
            break;
        }

        client_socket.write(&mut input.as_bytes());
        let mut buffer:Vec<u8> = Vec::new();
        let mut reader = BufReader::new(&client_socket);
        reader.read_until(b'\0', &mut buffer);
        println!("Received: {}", String::from_utf8_lossy(&buffer));
    }

    drop(listner);
}
