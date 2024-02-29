use std::io::Write;
use std::sync::mpsc::{channel, Sender};
use std::{env, io, thread, u16};
use std::net::{IpAddr, TcpStream};
use std::str::FromStr;
use std::process;

const MAX_PORT: u16 = 65535;

struct Arguments {
    ipaddress: IpAddr,
    threads: u16,
}

impl Arguments {
    fn new(args: &[String]) -> Result<Arguments, &'static str> {

        // If less than 2 arguments, not enough
        if args.len() < 2 {
            return Err("Not enough arguments");
        } 
        
        // If more than 4 arguments provided, too many
        if args.len() > 4 {
            return Err("Too many arguments");
        }

        // If ip address provided first, then we don't care about the rest and scan this address
        let flag = args[1].clone();

        if let Ok(ipaddress) = IpAddr::from_str(&flag){
            return Ok(Arguments {ipaddress, threads:4});
        }

        // command with - passed first, either -h or -j
        if flag.contains("-h") || flag.contains("-help") {

            // Correct usage of help command, displaying it
            if args.len() == 2{
                println!("Usage : \r\n-j to select how many threads you want \r\n-h or -help to show this help message");

                println!("\nExample : \r\nip_sniffer -j <number of threads> <ip to scan> \r\nip_sniffer <ip to scan>\n");

                return Err("Help");
            } 

            // Too many args for help command
            return Err("Too many arguments");
        }

        // Case where first argument should be -j = [1], <number of threads> = [2] and ip to scan [3]
        if !flag.contains("-j") || args.len() != 4 {
            return Err("Invalid syntax");
        }

        // Getting the IpAddress into its object
        let ipaddress = match IpAddr::from_str(&args[3]) {
            Ok(s) => s,
            Err(_) => return Err("Not a valid Ip address; must be ipv4 or ipv6")
        };

        // Parsing the given tread number 
        let threads = match args[2].parse::<u16>(){
            Ok(s) => s,
            Err(_) => return Err("Failed to parse thread number")
        };

        Ok(Arguments{threads, ipaddress})
        
    }
}

fn scan(tx: Sender<u16>, start_port:u16, ip_address: IpAddr, number_of_threads: u16){

    let mut port: u16 = start_port + 1;

    loop {

        match TcpStream::connect((ip_address,port)) {
            Ok(_) => {
                print!(".");
                io::stdout().flush().unwrap();
                tx.send(port).unwrap();
            }

            Err(_) => {}
        }

        if (MAX_PORT - port) <= number_of_threads{
            break;
        }

        port += number_of_threads;
    }
}


fn main() {

    println!("\n=== Welcome to ip-sniffer ===\n");

    let args: Vec<String> = env::args().collect();

    let program = args[0].clone();

    // Loading program arguments from command line into the struct
    let arguments = Arguments::new(&args).unwrap_or_else(
        |err| {
            if err.contains("Help") {
                process::exit(0);
            }

            else{
                eprintln!("{} problem parsing arguments: {}", program, err);
                process::exit(0);
            }
        }
    );

    let num_threads = arguments.threads;

    let (tx, rx) = channel();

    for i in 0..num_threads {
        let tx = tx.clone();

        thread::spawn(move || {
            scan(tx, i, arguments.ipaddress, num_threads);
        });
    }

    let mut out = vec![];

    drop(tx);

    // Extract ports found from receiver, put into out
    for p in rx {
        out.push(p);
    }

    println!("");
    
    // Sort by increasing port 
    out.sort();

    // Printing opened ports
    for v in out {
        println!("{} is open", v);
    }

    // Pretty print
    println!();

}
