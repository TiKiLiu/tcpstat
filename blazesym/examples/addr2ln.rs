extern crate blazesym;

use blazesym::{BlazeSymbolizer, SymbolSrcCfg};
use std::env;

fn show_usage() {
    let args: Vec<String> = env::args().collect();
    println!("Usage: {} <file> <address>", args[0]);
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        show_usage();
        return;
    }

    let bin_name = &args[1];
    let mut addr_str = &args[2][..];
    let sym_srcs = [SymbolSrcCfg::Elf {
        file_name: bin_name.clone(),
        base_address: 0x0,
    }];
    let resolver = BlazeSymbolizer::new().unwrap();

    if &addr_str[0..2] == "0x" {
        // Remove prefixed 0x
        addr_str = &addr_str[2..];
    }
    let addr = u64::from_str_radix(addr_str, 16).unwrap();

    let results = resolver.symbolize(&sym_srcs, &[addr]);
    if results.len() == 1 && results[0].len() > 0 {
        let result = &results[0][0];
        println!(
            "0x{:x} @ {} {}:{}",
            addr, result.symbol, result.path, result.line_no
        );
    } else {
        println!("0x{:x} is not found", addr);
    }
}
