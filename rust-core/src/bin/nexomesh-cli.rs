use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("nexomesh-cli: commands: keygen, status");
        return;
    }
    match args[1].as_str() {
        "keygen" => println!("generated key"),
        "status" => println!("status ok"),
        _ => println!("unknown command"),
    }
}
