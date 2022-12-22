extern crate clap;

use clap::Parser;

#[derive(Parser, Debug)]
#[clap(name = "clicky-bunty-server")]
#[clap(author = "dump@dvb.solutions")]
#[clap(version = "0.1.0")]
#[clap(about = "management server for dump-dvb", long_about = None)]
pub struct Args {
    #[arg(short, long, default_value_t = String::from("127.0.0.1"))]
    pub api_host: String,

    #[arg(short, long, default_value_t = 8080)]
    pub port: u16,

    #[arg(short, long, action)]
    pub swagger: bool,
}

