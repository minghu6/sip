use std::env;

use clap::Parser;
use linuxc::iface::get_available_ipv4_ifname;
use log::info;
use sip::dev::NetDevice;
use anyhow::anyhow;

/// Simple UDP/IP Network Protocol Stack
#[derive(Parser)]
#[clap(name = "SIP")]
struct Cli {
    /// If name
    #[arg(short)]
    ifname: Option<String>,
}

fn setup_logger() -> anyhow::Result<()> {
    /* Logger should be configured first! */
    let mut logconf = log4rs::config::load_config_file(
        "log4rs.default.yaml",
        Default::default(),
    )?;

    if let Ok(levels) = env::var("RUST_LOG") {
        match levels.parse() {
            Ok(level) => {
                logconf.root_mut().set_level(level);
            }
            Err(err) => Err(err)?,
        }
    }

    log4rs::init_config(logconf)?;

    Ok(())
}


fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let ifname = match cli.ifname {
        Some(ifname) => ifname,
        None => {
            let mut ifname_list = get_available_ipv4_ifname()?;

            if ifname_list.is_empty() {
                Err(anyhow!("No available ifname"))?
            }

            ifname_list.remove(0)
        },
    };

    setup_logger().unwrap();

    let dev = NetDevice::init(ifname.as_str()).unwrap();

    info!("dev init: {:#?}", dev);

    loop {
        match dev.input() {
            Ok(_) => (),
            Err(err) => println!("{err:#?}"),
        }
    }
}
