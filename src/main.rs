use anyhow::{Result};
use clap::Parser;
use std::str::FromStr;
use cidr::{Ipv4Cidr, Ipv6Cidr};
use tracing::{info};
use syslog_tracing::{Syslog};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;
use daemonize::Daemonize;
use hostwatch::Args;
use hostwatch::HostWatch;



fn main() -> Result<()> {
    let args = Args::parse();

    /***
     * Initialize logging
     */
    let level = if args.verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };

    let stdout_layer = if args.foreground {
        /* log to stdout when running in foreground */
        Some(tracing_subscriber::fmt::layer().with_writer(std::io::stdout))
    } else {
        None
    };

    let syslog_layer_opt = if args.syslog {
        let identity = std::ffi::CStr::from_bytes_with_nul(b"hostwatch\0")?;
        let (options, facility) = Default::default();
        let syslog = Syslog::new(identity, options, facility).unwrap();
        Some(tracing_subscriber::fmt::layer()
            .pretty()
            .with_ansi(false)
            .with_line_number(false)
            .with_file(false)
            .with_writer(syslog))
    } else {
        None
    };

    let filter = EnvFilter::from_default_env()
        .add_directive(format!("hostwatch={}", level).parse()?);
    tracing_subscriber::registry().with(filter).with(stdout_layer).with(syslog_layer_opt).init();

    if !args.interface.contains(&"any".to_string()) && !args.filename.clone().unwrap_or("".to_string()).is_empty() {
        println!("File [-F] and interface [-i] modes can not be combined");
        std::process::exit(1);
    }
    info!("Starting hostwatch on interface: {:?}", args.interface);
    info!("Database: {}", args.database);
    info!("OUI path: {}", args.oui_path);
    if !args.promisc {
        info!("Promiscuous mode enabled");
    }

    // validate networks, bail when invalid
    for network in args.skip_nets.iter() {
        let is_valid = match Ipv4Cidr::from_str(network) {
            Ok(_cidr) => true,
            Err(_e) => match Ipv6Cidr::from_str(network) {
                Ok(_cidr) => true,
                Err(_e) => false
            }
        };
        if !is_valid {
            println!("Network {} not valid", network);
            std::process::exit(1);
        } else {
            info!("Skipping network: {}", network);
        }
    }

    let hostwatch = HostWatch::new(args.clone());
    if args.foreground {
        hostwatch?.init().run()?;
    } else {
        let mut daemonize = Daemonize::new()
            .umask(args.clone().umask)
            .pid_file(args.clone().pid_file.as_str())
            .chown_pid_file(args.chown_pid_file)
            .working_directory(args.clone().working_directory.unwrap().as_str())
            .privileged_action(|| {
                hostwatch.expect("Unable to initialize captures").init()
            });

        if args.clone().user.is_some() {
            daemonize = daemonize.user(args.clone().user.unwrap().as_str());
        }
        if args.clone().group.is_some() {
            daemonize = daemonize.user(args.clone().group.unwrap().as_str());
        }

        match daemonize.start() {
            Ok(child) => {
                child.run().expect("Failed to execute captures")
            },
            Err(e) => eprintln!("Error, {}", e),
        }
    }

    Ok(())
}
