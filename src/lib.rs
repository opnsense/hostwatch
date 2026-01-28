use std::sync::{mpsc};
use std::sync::mpsc::Sender;
use std::thread;
use anyhow::{anyhow, Result};
use pcap::{Active, Activated, Offline, Capture, Device, Error as PcapError};
use clap::Parser;
use tracing::{debug, error, info};
use pnet::packet::arp::ArpPacket;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::{ethernet::EthernetPacket, Packet};
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::icmpv6::{Icmpv6Packet, Icmpv6Types};
use pnet::packet::icmpv6::ndp::NeighborSolicitPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use std::net::Ipv6Addr;

pub mod database;

use database::Database;
use database::HostInfo;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Network interface to monitor
    #[arg(short, long, default_value = "any")]
    pub interface: Vec<String>,

    /// pcap file source
    #[arg(short='F', long)]
    pub filename: Option<String>,

    /// Networks to ignore
    #[arg(short, long)]
    pub skip_nets: Vec<String>,

    /// Database file path
    #[arg(short, long, default_value = "hosts.db")]
    pub database: String,

    /// Path to oui.csv source file
    #[arg(short, long, default_value = "/usr/local/opnsense/contrib/ieee/oui.csv")]
    pub oui_path: String,

    /// Disable promiscuous mode
    #[arg(short, long)]
    pub promisc: bool,

    /// Verbose output
    #[arg(short, long)]
    pub verbose: bool,

    /// PID file
    #[arg(short='P', long, default_value="/var/run/hostwatch.pid")]
    pub pid_file: String,

    /// Username to use after startup
    #[arg(short, long)]
    pub user: Option<String>,

    /// Groupname to use after startup
    #[arg(short, long)]
    pub group: Option<String>,

    /// Umask of the PID file
    #[arg(short='U', long, value_parser = parse_permissions, default_value = "027")]
    pub umask: u32,

    /// Chown the PID file
    #[arg(short, long, action = clap::ArgAction::SetTrue, default_value_t = false)]
    pub chown_pid_file: bool,

    /// Working dir
    #[arg(short, long, default_value = "/tmp")]
    pub working_directory: Option<String>,

    /// Activity timeout [seconds] (report when > x)
    #[arg(short, long, default_value = "2678400")]
    pub activity_timeout: u32,

    /// Send output to syslog
    #[arg(short='S', long, action = clap::ArgAction::SetTrue, default_value_t = false)]
    pub syslog: bool,

    /// do not daemonize, run in foreground
    #[arg(short, long, action = clap::ArgAction::SetTrue, default_value_t = false)]
    pub foreground: bool,
}

fn parse_permissions(string: &str) -> Result<u32, anyhow::Error> {
    let val = u32::from_str_radix(string, 8);
    if val.clone().is_err() ||val.clone()? > 4095 {
        Err(anyhow!("Invalid permissions"))
    } else {
        Ok(val?)
    }
}

pub struct HostWatch {
    interfaces: Vec<String>,
    filename: Option<String>,
    system_interfaces: Vec<String>,
    database: String,
    oui_path: String,
    device_captures: Vec<Capture<Active>>,
    file_captures: Vec<Capture<Offline>>,
    pcap_filter: String,
    promisc: bool,
    activity_timeout: u32
}

impl HostWatch {
    pub fn new(args: Args) -> Result<Self> {
        let interfaces = &args.interface.iter().map(|s| s.as_str()).collect::<Vec<_>>();
        let mut pcap_filter = Vec::new();
        pcap_filter.push("(\
            (arp && not src 0) || \
            (\
                icmp6 && (icmp6[icmp6type] == icmp6-neighborsolicit || \
                icmp6[icmp6type] == icmp6-neighboradvert) \
            ))\
         ".to_string());
        for item in args.clone().skip_nets.iter() {
            pcap_filter.push(format!("( net !{} )", item.as_str()));
        }
        Ok(Self {
            interfaces: interfaces.iter().map(|s| s.to_string()).collect(),
            filename: args.clone().filename,
            system_interfaces: Vec::new(),
            database: args.clone().database,
            oui_path: args.clone().oui_path,
            device_captures: Vec::new(),
            file_captures: Vec::new(),
            promisc: args.clone().promisc,
            activity_timeout: args.activity_timeout,
            pcap_filter: pcap_filter.join(" && ")
        })
    }


    pub fn init(mut self) ->  Self {
        self.device_captures.clear();
        self.file_captures.clear();
        self.system_interfaces.clear();
        debug!("pcap filter is: {:?}", self.pcap_filter);

        if self.filename.is_some() {
            info!("Initializing packet capture on file: {:?}", self.filename.clone().unwrap());
            #[allow(clippy::single_match)]
            match self.initialize_file_captures() {
                Ok(_) => {}
                Err(_) => {}
            }
        } else {
            info!("Initializing packet capture on interfaces: {:?}", self.interfaces);
            #[allow(clippy::single_match)]
            match self.initialize_device_captures() {
                Ok(_) => {}
                Err(_) => {}
            }
            info!("Starting packet capture loop on {} interfaces...", self.device_captures.len());
        }
        self
    }

    pub fn run(mut self) -> Result<()> {
        // start a thread per interface capture
        let (tx, rx) = mpsc::channel::<HostInfo>();
        for (i, capture) in self.device_captures.drain(..).enumerate() {
            let interface_name = self.system_interfaces[i].clone();
            let tx_clone = tx.clone();
            thread::spawn(move || {
                Self::capture_packets(capture, interface_name, tx_clone)
            });
        }
        for capture in self.file_captures.drain(..) {
            let tx_clone = tx.clone();
            thread::spawn(move || {
                Self::capture_packets(capture, "pcap".to_string(), tx_clone)
            });
        }
        drop(tx); // unused original sender

        // process messages to database in main thread
        let mut database = Database::new(self.database, self.oui_path)?;
        for host_info in rx {
            debug!("discover packet: {:?}", host_info);
            let host_info = database.update_host(&host_info)?;
            /* Signal events via logging */
            if host_info.clone().is_some_and(|x| x.was_inserted == Some(1)){
                info!(
                    "new station host {} using {} at {}",
                    host_info.clone().unwrap().ether_address.unwrap_or_else(|| String::from("")),
                    host_info.clone().unwrap().ip_address.unwrap_or_else(|| String::from("")),
                    host_info.clone().unwrap().interface_name.unwrap_or_else(|| String::from(""))
                );
            } else if host_info.clone().is_some_and(|x| {
                    x.ether_address != x.prev_ether_address &&
                    x.sec_since_last_update.is_some_and(|x| x > -1) &&
                    x.ether_address.is_some() &&
                    x.prev_ether_address.is_some()
            }){
                info!(
                   "changed ethernet address host {} moved from {} to {} at {}",
                   host_info.clone().unwrap().ip_address.unwrap_or_else(|| String::from("")),
                   host_info.clone().unwrap().prev_ether_address.unwrap_or_else(|| String::from("")),
                   host_info.clone().unwrap().ether_address.unwrap_or_else(|| String::from("")),
                   host_info.clone().unwrap().interface_name.unwrap_or_else(|| String::from(""))
                );
            } else if host_info.clone().is_some_and(|x| {
                    x.ether_address != x.real_ether_address &&
                    x.real_ether_address != x.prev_real_ether_address &&
                    x.sec_since_last_update.is_some_and(|x| x > -1) &&
                    x.ether_address.is_some() &&
                    x.real_ether_address.is_some()
            }){
                info!(
                    "ethernet mismatch host {} at {} announced by {} interface {}",
                    host_info.clone().unwrap().ip_address.unwrap_or_else(|| String::from("")).as_str(),
                    host_info.clone().unwrap().ether_address.unwrap_or_else(|| String::from("")),
                    host_info.clone().unwrap().real_ether_address.unwrap_or_else(|| String::from("")),
                    host_info.clone().unwrap().interface_name.unwrap_or_else(|| String::from(""))
                );
            } else if host_info.clone().is_some_and(|x| x.sec_since_last_update.is_some_and(|x| x > self.activity_timeout as i32)) {
                info!(
                    "new station activity {} using {} at {} since {} seconds",
                    host_info.clone().unwrap().ether_address.unwrap_or_else(|| String::from("")),
                    host_info.clone().unwrap().ip_address.unwrap_or_else(|| String::from("")),
                    host_info.clone().unwrap().interface_name.unwrap_or_else(|| String::from("")),
                    host_info.clone().unwrap().sec_since_last_update.unwrap()
                );
            }

            debug!("processed: {:?}", host_info);
        }
        info!("done processing (no more active captures)");
        Ok(())
    }

    fn initialize_file_captures(&mut self) -> Result<()> {
        if let Ok(capture) = self.create_file_capture(self.filename.clone().unwrap()) {
            self.file_captures.push(capture);
            info!("Added capture for pcap file: {}", self.filename.clone().unwrap());
            Ok(())
        } else {
            error!("Failed to initialize capture for pcap file: {}", self.filename.clone().unwrap());
            Err(anyhow!("Failed to initialize file capture"))
        }
    }

    fn initialize_device_captures(&mut self) -> Result<()> {
        let devices = Device::list()?;

        for device in devices {
            if self.interfaces.contains(&"any".to_string()) || self.interfaces.contains(&device.name.clone()) {
                if let Ok(capture) = self.create_device_capture(&device) {
                    let datalink = capture.get_datalink();
                    if datalink != pcap::Linktype::ETHERNET {
                        info!("Skip capture for device: {} Link type: {:?}", device.name, datalink);
                        continue;
                    }
                    self.device_captures.push(capture);
                    self.system_interfaces.push(device.name.clone());
                    info!("Added capture for device: {} ({})",
                          device.name,
                          device.desc.as_deref().unwrap_or("No description"));
                } else {
                    info!("Skip capture for device: {}", device.name);
                }
            }
        }
        if self.device_captures.is_empty() {
            return Err(anyhow::anyhow!("No captures could be initialized"));
        }

        info!("Initialized {} packet device_captures", self.device_captures.len());
        Ok(())
    }

    fn create_file_capture(&self, filename: String) -> Result<Capture<Offline>>
    {
        let mut capture = Capture::from_file(filename)?;
        capture.filter(self.pcap_filter.as_str(), true)?;
        Ok(capture)
    }

    fn create_device_capture(&self, device: &Device) -> Result<Capture<Active>> {
        let mut capture = Capture::from_device(device.clone())?
            .promisc(!self.promisc)
            .snaplen(65535)
            .timeout(1000)
            .open()?;

        capture.filter(self.pcap_filter.as_str(), true)?;

        Ok(capture)
    }

    fn capture_packets<T>(mut capture: Capture<T>, interface_name: String, tx: Sender<HostInfo>)
        where T: Activated,
    {
        loop {
            match capture.next_packet() {
                Ok(packet) => {
                    let ethernet = EthernetPacket::new(packet.data).unwrap();

                    let mut host_info = HostInfo::new();
                    host_info.interface_name = Some(interface_name.clone());
                    host_info.real_ether_address = Some(ethernet.get_source().to_string());
                    if ethernet.get_ethertype() == EtherTypes::Arp {
                        if let Some(arp) = ArpPacket::new(ethernet.payload()) {
                            host_info.protocol = Some("inet".to_string());
                            host_info.ether_address = Some(arp.get_sender_hw_addr().to_string());
                            host_info.ip_address = Some(arp.get_sender_proto_addr().to_string());
                        }
                    } else if ethernet.get_ethertype() == EtherTypes::Ipv6 {
                        if let Some(ipv6) = Ipv6Packet::new(ethernet.payload()) {
                            if ipv6.get_next_header() != IpNextHeaderProtocols::Icmpv6 {
                                return;
                            }
                            let icmpv6 = match Icmpv6Packet::new(ipv6.payload()) {
                                Some(pkt) => pkt,
                                None => return,
                            };
                            host_info.ether_address = Some(ethernet.get_source().to_string());
                            host_info.protocol = Some("inet6".to_string());
                            if ipv6.get_source() == Ipv6Addr::UNSPECIFIED && icmpv6.get_icmpv6_type() == Icmpv6Types::NeighborSolicit {
                                /* Duplicate Address Detection (DAD) can be used to find the GUA/LUA a client intends to use*/
                                if let Some(ns) = NeighborSolicitPacket::new(icmpv6.packet()) {
                                    host_info.ip_address = Some(ns.get_target_addr().to_string());
                                }
                            } else if ipv6.get_source() != Ipv6Addr::UNSPECIFIED {
                                /* the actual address used by the client, usually a LL */
                                host_info.ip_address = Some(ipv6.get_source().to_string());
                            }
                        }
                    }
                    if host_info.ip_address.is_some() {
                        tx.send(host_info).unwrap();
                    }
                }
                Err(PcapError::TimeoutExpired) => {
                    // Timeout is expected, continue
                }
                Err(PcapError::NoMorePackets) => {
                    // File mode, exit when file is fully read
                    break;
                }
                Err(e) => {
                    /* XXX: not sure if there are errors we can recover from, for now assume cycling will lead to the same issue */
                    error!("Error reading from capture: {}, exit {}", e, interface_name);
                    break;
                }
            }
        }
    }
}
