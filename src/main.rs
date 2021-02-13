#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!("../target/bindings.rs");

use clap::{App, Arg};
use gethostname::gethostname;
use log::*;
use serde_derive::Deserialize;
use std::{fs::File, io::Read};

#[derive(Deserialize)]
struct Config {
    host: Vec<Host>,
    name: Option<String>,
}

#[derive(Deserialize)]
struct Host {
    name: String,
    data: Option<String>,
    log: Option<String>,
    advertise_client: String,
    listen_client: String,
    advertise_peer: String,
    listen_peer: String,
}

pub fn go_string(s: &str) -> GoString {
    GoString {
        p: s.as_bytes().as_ptr() as *const i8,
        n: s.len() as isize,
    }
}

fn main() -> anyhow::Result<()> {
    env_logger::init();

    let matches = App::new("daccountd")
        .arg(
            Arg::with_name("name")
                .short("n")
                .long("name")
                .value_name("NAME")
                .help("Override node name")
                .takes_value(true),
        )
        .get_matches();

    let mut buffer = vec![];
    let mut file = File::open("config.toml")?;
    file.read_to_end(&mut buffer)?;
    let config: Config = toml::from_slice(&buffer)?;

    let name = matches
        .value_of("name")
        .map(|s| s.to_string())
        .or(config.name)
        .unwrap_or_else(|| gethostname().to_string_lossy().to_string());
    info!("This node name is {}", name);

    if let Some(host) = config.host.iter().find(|h| h.name == name) {
        let data = host.data.clone().unwrap_or(format!("data-{}", name));
        let log = host.log.clone().unwrap_or(format!("etcd-{}.log", name));
        let initial_cluster = config
            .host
            .iter()
            .map(|h| format!("{}={}", h.name, h.advertise_peer))
            .collect::<Vec<String>>()
            .join(",");
        unsafe {
            Run(
                go_string(&data),
                go_string(&host.name),
                go_string(&initial_cluster),
                go_string("info"),
                go_string(&log),
                go_string(&host.advertise_client),
                go_string(&host.listen_client),
                go_string(&host.advertise_peer),
                go_string(&host.listen_peer),
            );
        }
        info!(
            "Etcd server started at peer {} client {} initial cluster {}",
            host.listen_peer, host.listen_client, initial_cluster
        );
        info!("Initial cluster is {}", initial_cluster);
        info!("Etcd data is located at {}", data);
        info!("Etcd is logged to {}", log);
        loop {}
    } else {
        error!("No matching configuration found for host {}", name);
    }
    Ok(())
}
