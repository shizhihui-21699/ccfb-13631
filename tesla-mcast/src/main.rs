mod attacker;
mod common;
mod receiver;
mod sender;

fn usage() {
    eprintln!(
        "usage:
  tesla-mcast sender   [--rate 20000] [--interval-ms 100] [--delay 2] [--chain 500000] [--ckpt-every 20] [--group 239.255.42.99] [--port 5000]
  tesla-mcast receiver [--drop 0.1] [--duration 30] [--group 239.255.42.99] [--port 5000]
  tesla-mcast attacker [--rate 2000] [--delay 2] [--group 239.255.42.99] [--port 5000]"
    );
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        usage();
        return;
    }
    let res = match args[1].as_str() {
        "sender" => sender::run(&args[2..]),
        "receiver" => receiver::run(&args[2..]),
        "attacker" => attacker::run(&args[2..]),
        _ => {
            usage();
            return;
        }
    };
    if let Err(e) = res {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
