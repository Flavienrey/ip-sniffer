use std::env;

// Syntax to accept
//  ip_sniffer -h
//  ip_sniffer -j <number of threads> <ip to scan>
//  ip_sniffer <ip to scan>

fn main() {

    let args: Vec<String> = env::args().collect();

    for arg in &args {
        println!("{}", arg);
    }

    println!("{:?}", args);
}


