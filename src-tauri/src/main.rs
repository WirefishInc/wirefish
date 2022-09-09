extern crate pnet;
extern crate sniffer_parser;
extern crate sudo;

mod report;

use dotenv;
use env_logger::Builder;
use log::{error, info};
use std::io::Write;

use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, ChannelType, Config, DataLinkReceiver, NetworkInterface};
use pnet::packet::ethernet::EthernetPacket;

use tauri::async_runtime::Mutex;
use tauri::{async_runtime, State, Manager, Window, Wry};
use report::{write_report, data::{SourceDestination, PacketExchange}};
use std::collections::HashMap;
use chrono::Local;

use std::sync::Arc;
use std::cell::RefCell;
use tauri_awesome_rpc::{AwesomeEmit, AwesomeRpc};

use sniffer_parser::{parse_ethernet_frame, serializable_packet::{SerializablePacket, ParsedPacket}};

struct SniffingInfoState(Arc<Mutex<SniffingInfo>>); // TODO: I think it would be better to have a mutex for the interface and one for the hashmap
struct SniffingInfo {
    interface_channel: Option<Box<dyn DataLinkReceiver>>,
    interface_name: Option<String>,
    exchanged_packets: RefCell<HashMap<SourceDestination, PacketExchange>>,
    is_sniffing: bool,
}

impl SniffingInfo {
    fn new() -> Self {
        SniffingInfo {
            interface_channel: None,
            interface_name: None,
            exchanged_packets: RefCell::new(HashMap::<SourceDestination, PacketExchange>::new()),
            is_sniffing: false,
        }
    }
}

#[tauri::command]
async fn get_interfaces_list() -> Vec<String> {
    let interfaces = datalink::interfaces()
        .into_iter()
        .map(|i| if cfg!(target_os = "windows") { i.description } else { i.name } )
        .collect::<Vec<String>>();
    info!("Interfaces retrieved: {:#?}", interfaces);

    interfaces
}

#[tauri::command]
async fn select_interface(
    state: tauri::State<'_, SniffingInfoState>,
    interface_name: String,
) -> Result<(), ()> {
    let interface_names_match = |iface: &NetworkInterface|
        if cfg!(target_os = "windows") { iface.description == interface_name } else { iface.name == interface_name};

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap();

    info!("Interface selected: {}", interface_name);

    let config = Config {
        write_buffer_size: 16384,
        read_buffer_size: 16384,
        read_timeout: None,
        write_timeout: None,
        channel_type: ChannelType::Layer2,
        bpf_fd_attempts: 1000,
        linux_fanout: None,
        promiscuous: true,
    };

    // Create a new channel, dealing with layer 2 packets
    let (_, rx) = match datalink::channel(&interface, config) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!(
            "An error occurred when creating the datalink channel: {}",
            e
        ),
    };

    let mut sniffing_state = state.0.lock().await;
    sniffing_state.interface_channel = Some(rx);
    sniffing_state.interface_name = Some(interface_name);

    info!(
        "[{}] Channel created",
        sniffing_state.interface_name.as_ref().unwrap()
    );

    Ok(())
}

#[tauri::command]
async fn start_sniffing(
    state: tauri::State<'_, SniffingInfoState>,
    window: Window<Wry>,
) -> Result<(), String> {
    let mut sniffing_state = state.0.lock().await;

    if sniffing_state.interface_name.is_none() {
        error!("Start sniffing without prior selection of the inteface");
        return Err("Start sniffing without prior selection of the inteface".to_owned());
    }

    sniffing_state.is_sniffing = true;
    info!(
        "[{}] Sniffing started",
        sniffing_state.interface_name.as_ref().unwrap()
    );

    let ss = Arc::clone(&state.0);
    async_runtime::spawn(async move {
        loop {
            let mut sniffing_state = ss.lock().await;

            if !sniffing_state.is_sniffing {
                break;
            }

            match sniffing_state.interface_channel.as_mut().unwrap().next() {
                Ok(packet) => {
                    let ethernet_packet = EthernetPacket::new(packet).unwrap();
                    let new_packet = parse_ethernet_frame(&ethernet_packet);

                    /* Save packet in HashMap */
                    let now = Local::now();
                    let sender_receiver = get_sender_receiver(&new_packet);
                    let mut transmitted_bytes = 0;
                    let mut protocol = String::from("-");
                    if let SerializablePacket::EthernetPacket(link_packet) = new_packet.get_link_layer_packet().unwrap() {
                        transmitted_bytes = link_packet.payload.len();
                        protocol = link_packet.ethertype.clone();
                    }
                    sniffing_state.exchanged_packets.borrow_mut()
                        .entry(sender_receiver)
                        .and_modify(|exchange| exchange.add_packet(protocol.clone(), transmitted_bytes, now))
                        .or_insert(PacketExchange::new(protocol, transmitted_bytes, now));

                    window
                        .state::<AwesomeEmit>()
                        .emit("main", "packet_received", new_packet);
                }
                Err(e) => {
                    // If an error occurs, we can handle it here
                    error!("An error occurred while reading");
                    panic!("An error occurred while reading: {}", e);
                }
            }

            // drop(sniffing_state);
        }
    });

    Ok(())
}

fn get_sender_receiver(packet: &ParsedPacket) -> SourceDestination {
    let mut network_source = String::from("-");
    let mut network_destination = String::from("-");
    let mut transport_source = String::from("-");
    let mut transport_destination = String::from("-");
    let network_packet_wrapper = packet.get_network_layer_packet();
    if network_packet_wrapper.is_some() {
        match network_packet_wrapper.unwrap() {
            SerializablePacket::ArpPacket(network_packet) => {
                network_source = network_packet.sender_proto_addr.to_string();
                network_destination = network_packet.target_proto_addr.to_string();
            },
            SerializablePacket::Ipv4Packet(network_packet) => {
                network_source = network_packet.source.to_string();
                network_destination = network_packet.destination.to_string();
            },
            SerializablePacket::Ipv6Packet(network_packet) => {
                network_source = network_packet.source.to_string();
                network_destination = network_packet.destination.to_string();
            },
            _ => {}
        }
    }
    let transport_packet_wrapper = packet.get_transport_layer_packet();
    if transport_packet_wrapper.is_some() {
        match transport_packet_wrapper.unwrap() {
            SerializablePacket::TcpPacket(transport_packet) => {
                transport_source = transport_packet.source.to_string();
                transport_destination = transport_packet.destination.to_string();
            },
            SerializablePacket::UdpPacket(transport_packet) => {
                transport_source = transport_packet.source.to_string();
                transport_destination = transport_packet.destination.to_string();
            },
            _ => {}
        }
    }
    // Todo: Handle arp packets source and destination
    SourceDestination::new(network_source, network_destination, transport_source, transport_destination)
}

#[tauri::command]
async fn stop_sniffing(state: tauri::State<'_, SniffingInfoState>) -> Result<(), ()> {
    let mut sniffing_state = state.0.lock().await;
    sniffing_state.is_sniffing = false;

    // TODO: Empty sniffing_state.exchanged_packets on stop (not on pause)

    info!(
        "[{}] Sniffing stopped",
        sniffing_state.interface_name.as_ref().unwrap()
    );

    Ok(())
}

#[tauri::command]
async fn generate_report(state: tauri::State<'_, SniffingInfoState>, report_path: String, first_generation: bool) -> Result<bool, String> {
    let sniffing_state = state.0.lock().await;
    let exchanged_packets = sniffing_state.exchanged_packets.take();
    drop(sniffing_state);
    let sniffing_state2 = state.0.lock().await;
    let result = write_report(&report_path, exchanged_packets, first_generation);
    return match result {
        Err(why) => Err(why.to_string()),
        Ok(_) => Ok(true)
    }
}

fn main() {
    dotenv::dotenv().ok();
    if !cfg!(target_os = "windows") {
        // sudo::escalate_if_needed();
    }

    // env_logger::init();

    let mut builder = Builder::from_default_env();
    builder
        .format(|buf, r| {
            writeln!(buf, "[{}] {}", buf.default_styled_level(r.level()), r.args())
        })
        .init();

    let awesome_rpc = AwesomeRpc::new(vec!["tauri://localhost", "http://localhost:*"]);

    tauri::Builder::default()
        .invoke_system(awesome_rpc.initialization_script(), AwesomeRpc::responder())
        .setup(move |app| {
            awesome_rpc.start(app.handle());
            Ok(())
        })
        .manage(SniffingInfoState(Arc::new(Mutex::new(SniffingInfo::new()))))
        .invoke_handler(tauri::generate_handler![
            start_sniffing,
            stop_sniffing,
            get_interfaces_list,
            generate_report,
            select_interface
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}