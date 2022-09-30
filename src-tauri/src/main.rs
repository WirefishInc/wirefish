extern crate pnet;
extern crate sniffer_parser;
extern crate sudo;
extern crate core;

mod filtering;
mod report;

use dotenv;
use env_logger::Builder;
use log::{error, info};
use serde::Serialize;
use sniffer_parser::serializable_packet::util::{
    contains_arp, contains_dns, contains_ethernet, contains_http, contains_icmp, contains_icmp6,
    contains_ipv4, contains_ipv6, contains_malformed, contains_tcp, contains_tls, contains_udp,
    contains_unknokn, get_dest_ip, get_dest_mac, get_dest_port, get_source_ip, get_source_mac,
    get_source_port,
};
use std::io::Write;

use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, ChannelType, Config, NetworkInterface};
use pnet::packet::ethernet::EthernetPacket;

use chrono::Local;
use filtering::{get_packets, PacketsCollection};
use report::{
    data::{PacketExchange, SourceDestination},
    write_report,
};
use std::collections::HashMap;
use tauri::{Window, Wry};

use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};

use sniffer_parser::{
    cleanup_sniffing_state, parse_ethernet_frame,
    serializable_packet::{ParsedPacket, SerializablePacket},
};

const CONFIG: Config = Config {
    write_buffer_size: 16384,
    read_buffer_size: 16384,
    read_timeout: None,
    write_timeout: None,
    channel_type: ChannelType::Layer2,
    bpf_fd_attempts: 1000,
    linux_fanout: None,
    promiscuous: true,
};

#[derive(Serialize, Debug)]
#[serde(tag = "type", content = "description")]
pub enum SniffingError {
    InterfaceNotFound(String),
    StartSniffingWithoutInterfaceSelection(String),
    GetPacketsIndexNotValid(String),
    UnhandledChannelType(String),
    FailedChannelCreation(String),
    StopSniffingWithoutPriorStart(String),
    ReportGenerationFailed(String),
    ReadingChannelFailed(String),
    UnknownFilterType(String),
}

pub struct SniffingState {
    sniffers: Arc<Mutex<HashMap<String, (Sender<()>, Receiver<SniffingError>)>>>,
    exchanged_packets: Arc<Mutex<HashMap<SourceDestination, PacketExchange>>>,
    info: Arc<Mutex<SniffingInfo>>,
    packets: Arc<Mutex<PacketsCollection>>,
}

impl SniffingState {
    fn new() -> Self {
        Self {
            sniffers: Arc::new(Mutex::new(HashMap::new())),
            exchanged_packets: Arc::new(Mutex::new(HashMap::new())),
            info: Arc::new(Mutex::new(SniffingInfo::new())),
            packets: Arc::new(Mutex::new(PacketsCollection::new())),
        }
    }
}

struct SniffingInfo {
    interface_name: Option<String>,
    interface: Option<NetworkInterface>,
}

impl SniffingInfo {
    fn new() -> Self {
        SniffingInfo {
            interface_name: None,
            interface: None,
        }
    }
}

#[tauri::command]
fn get_interfaces_list() -> Vec<String> {
    let interfaces = datalink::interfaces()
        .into_iter()
        .map(|i| {
            if cfg!(target_os = "windows") {
                i.description
            } else {
                i.name
            }
        })
        .collect::<Vec<String>>();
    info!("Interfaces retrieved: {:#?}", interfaces);

    interfaces
}

#[tauri::command]
fn select_interface(
    state: tauri::State<SniffingState>,
    interface_name: String,
) -> Result<(), SniffingError> {
    let interface_names_match = |iface: &NetworkInterface| {
        if cfg!(target_os = "windows") {
            iface.description == interface_name
        } else {
            iface.name == interface_name
        }
    };

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(interface_names_match)
        .next()
        .ok_or(SniffingError::InterfaceNotFound(
            "The provided interface is inexistent".to_owned(),
        ))?;

    info!("Interface selected: {}", interface_name);

    let mut sniffing_info = state.info.lock().unwrap();
    sniffing_info.interface = Some(interface);
    sniffing_info.interface_name = Some(interface_name);

    info!(
        "[{}] Channel created",
        sniffing_info.interface_name.as_ref().unwrap()
    );

    Ok(())
}

#[tauri::command]
fn start_sniffing(
    state: tauri::State<SniffingState>,
    window: Window<Wry>,
) -> Result<(), SniffingError> {
    let sniffing_state = state.info.lock().unwrap();
    let mut sniffers = state.sniffers.lock().unwrap();
    let mut packet_collection = state.packets.lock().unwrap();

    let interface_name = sniffing_state.interface_name.as_ref().ok_or(
        SniffingError::StartSniffingWithoutInterfaceSelection(
            "Start sniffing without prior selection of the inteface".to_owned(),
        ),
    )?;

    let interface = sniffing_state.interface.as_ref().ok_or(
        SniffingError::StartSniffingWithoutInterfaceSelection(
            "Start sniffing without prior selection of the interface".to_owned(),
        ),
    )?;

    packet_collection.clear();
    info!("[{}] Sniffing started", interface_name);

    let sniffer = sniffers.get_mut(interface_name);
    if sniffer.is_none() || sniffer.unwrap().0.send(()).is_err() {
        // Create a new channel, dealing with layer 2 packets
        let (_, mut interface_channel) = match datalink::channel(interface, CONFIG) {
            Ok(Ethernet(tx, rx)) => Ok((tx, rx)),
            Ok(_) => Err(SniffingError::UnhandledChannelType(
                "Unhandled channel type".to_owned(),
            )),
            Err(e) => {
                error!("Unexpected channel creation failure: {}", e);
                Err(SniffingError::FailedChannelCreation(
                    "Unexpected channel creation failure".to_owned(),
                ))
            }
        }?;

        let (send_stop, receive_stop) = channel();
        let (send_error, receive_error) = channel();

        sniffers.insert(interface_name.to_string(), (send_stop, receive_error));

        let exchanged_packets = Arc::clone(&state.exchanged_packets);
        let packets = Arc::clone(&state.packets);

        std::thread::spawn(move || {
            let mut counter_id = 0;

            loop {
                match interface_channel.next() {
                    Ok(packet) if receive_stop.try_recv().is_err() => {

                        let ethernet_packet = EthernetPacket::new(packet).unwrap();
                        let new_packet = parse_ethernet_frame(&ethernet_packet, counter_id);
                        counter_id += 1;

                        /* Save packet in HashMap */
                        let now = Local::now();
                        let sender_receiver = get_sender_receiver(&new_packet);
                        let mut transmitted_bytes = 0;
                        let mut protocols: Vec<String> = sender_receiver.1;
                        if let SerializablePacket::EthernetPacket(link_packet) =
                            new_packet.get_link_layer_packet().unwrap()
                        {
                            transmitted_bytes = link_packet.payload.len(); // TODO: Add ethernet header size
                            protocols.push(link_packet.ethertype.clone());
                        }

                        let mut packets_collection = packets.lock().unwrap();
                        let parsed_packet = Arc::new(new_packet);

                        // Index by Source IP
                        if let Some(ip_address) = get_source_ip(&parsed_packet) {
                            packets_collection
                                .source_ip_index
                                .entry(ip_address)
                                .and_modify(|packets| packets.push(Arc::clone(&parsed_packet)))
                                .or_insert(vec![Arc::clone(&parsed_packet)]);
                        }

                        // Index by Dest IP
                        if let Some(ip_address) = get_dest_ip(&parsed_packet) {
                            packets_collection
                                .dest_ip_index
                                .entry(ip_address)
                                .and_modify(|packets| packets.push(Arc::clone(&parsed_packet)))
                                .or_insert(vec![Arc::clone(&parsed_packet)]);
                        }

                        // Index by Source MAC
                        if let Some(mac_address) = get_source_mac(&parsed_packet) {
                            packets_collection
                                .source_mac_index
                                .entry(mac_address)
                                .and_modify(|packets| packets.push(Arc::clone(&parsed_packet)))
                                .or_insert(vec![Arc::clone(&parsed_packet)]);
                        }

                        // Index by Dest MAC
                        if let Some(mac_address) = get_dest_mac(&parsed_packet) {
                            packets_collection
                                .dest_mac_index
                                .entry(mac_address)
                                .and_modify(|packets| packets.push(Arc::clone(&parsed_packet)))
                                .or_insert(vec![Arc::clone(&parsed_packet)]);
                        }

                        // Index by Source Port
                        if let Some(port) = get_source_port(&parsed_packet) {
                            packets_collection
                                .source_port_index
                                .entry(port)
                                .and_modify(|packets| packets.push(Arc::clone(&parsed_packet)))
                                .or_insert(vec![Arc::clone(&parsed_packet)]);
                        }

                        // Index by Dest Port
                        if let Some(port) = get_dest_port(&parsed_packet) {
                            packets_collection
                                .dest_port_index
                                .entry(port)
                                .and_modify(|packets| packets.push(Arc::clone(&parsed_packet)))
                                .or_insert(vec![Arc::clone(&parsed_packet)]);
                        }

                        if contains_ethernet(&parsed_packet) {
                            packets_collection
                                .ethernet_packets
                                .push(parsed_packet.clone());
                        }

                        if contains_malformed(&parsed_packet) {
                            packets_collection
                                .malformed_packets
                                .push(parsed_packet.clone());
                        }

                        if contains_unknokn(&parsed_packet) {
                            packets_collection
                                .unknown_packets
                                .push(parsed_packet.clone());
                        }

                        if contains_tcp(&parsed_packet) {
                            packets_collection.tcp_packets.push(parsed_packet.clone());
                        }

                        if contains_udp(&parsed_packet) {
                            packets_collection.udp_packets.push(parsed_packet.clone());
                        }

                        if contains_icmp(&parsed_packet) {
                            packets_collection.icmp_packets.push(parsed_packet.clone());
                        }

                        if contains_icmp6(&parsed_packet) {
                            packets_collection
                                .icmpv6_packets
                                .push(parsed_packet.clone());
                        }

                        if contains_http(&parsed_packet) {
                            packets_collection.http_packets.push(parsed_packet.clone());
                        }

                        if contains_tls(&parsed_packet) {
                            packets_collection.tls_packets.push(parsed_packet.clone());
                        }

                        if contains_ipv4(&parsed_packet) {
                            packets_collection.ipv4_packets.push(parsed_packet.clone());
                        }

                        if contains_ipv6(&parsed_packet) {
                            packets_collection.ipv6_packets.push(parsed_packet.clone());
                        }

                        if contains_arp(&parsed_packet) {
                            packets_collection.arp_packets.push(parsed_packet.clone());
                        }

                        if contains_dns(&parsed_packet) {
                            packets_collection.dns_packets.push(parsed_packet.clone());
                        }

                        // Insert packet
                        packets_collection.packets.push(parsed_packet);

                        let mut exchanged_packets = exchanged_packets.lock().unwrap();
                        exchanged_packets
                            .entry(sender_receiver.0)
                            .and_modify(|exchange| {
                                exchange.add_packet(protocols.clone(), transmitted_bytes, now)
                            })
                            .or_insert(PacketExchange::new(protocols, transmitted_bytes, now));

                        let _result = window.emit("packet_received", ());
                    }
                    Ok(_) => {
                        // Clean the channel
                        while !receive_stop.try_recv().is_err() {}
                        break;
                    }
                    Err(e) => {
                        match send_error.send(SniffingError::ReadingChannelFailed(format!(
                            "Reading from channel failed: {}",
                            e
                        ))) {
                            _ => (),
                        }

                        // Clean the channel
                        while !receive_stop.try_recv().is_err() {}
                        break;
                    }
                }
            }
        });
    }

    Ok(())
}

fn get_sender_receiver(packet: &ParsedPacket) -> (SourceDestination, Vec<String>) {
    let mut network_source = String::from("-");
    let mut network_destination = String::from("-");
    let mut transport_source = String::from("-");
    let mut transport_destination = String::from("-");
    let mut protocols = Vec::new();
    let network_packet_wrapper = packet.get_network_layer_packet();
    if network_packet_wrapper.is_some() {
        match network_packet_wrapper.unwrap() {
            SerializablePacket::ArpPacket(network_packet) => {
                network_source = network_packet.sender_proto_addr.to_string();
                network_destination = network_packet.target_proto_addr.to_string();
            }
            SerializablePacket::Ipv4Packet(network_packet) => {
                network_source = network_packet.source.to_string();
                network_destination = network_packet.destination.to_string();
            }
            SerializablePacket::Ipv6Packet(network_packet) => {
                network_source = network_packet.source.to_string();
                network_destination = network_packet.destination.to_string();
            }
            _ => {}
        }
    }
    let transport_packet_wrapper = packet.get_transport_layer_packet();
    if transport_packet_wrapper.is_some() {
        match transport_packet_wrapper.unwrap() {
            SerializablePacket::TcpPacket(transport_packet) => {
                transport_source = transport_packet.source.to_string();
                transport_destination = transport_packet.destination.to_string();
                protocols.push("TCP".to_owned());
            }
            SerializablePacket::UdpPacket(transport_packet) => {
                transport_source = transport_packet.source.to_string();
                transport_destination = transport_packet.destination.to_string();
                protocols.push("UDP".to_owned());
            }
            _ => {}
        }
    }

    (
        SourceDestination::new(
            network_source,
            network_destination,
            transport_source,
            transport_destination,
        ),
        protocols,
    )
}

#[tauri::command]
/// stop: true => terminate sniffing process, false: pause sniffing process
fn stop_sniffing(state: tauri::State<SniffingState>, stop: bool) -> Result<(), SniffingError> {
    let sniffing_state = state.info.lock().unwrap();
    let mut sniffers = state.sniffers.lock().unwrap();

    let interface_name = sniffing_state.interface_name.as_ref().ok_or(
        SniffingError::StopSniffingWithoutPriorStart(
            "Stop sniffing without prior starting of the process".to_owned(),
        ),
    )?;

    let (send_stop, receive_error) = sniffers
        .get_mut(&sniffing_state.interface_name.as_ref().unwrap().to_string())
        .unwrap();

    match send_stop.send(()) {
        Ok(_) => {
            if let Ok(e) = receive_error.try_recv() {
                return Err(e);
            }
        }
        Err(_) => {
            // When Stop Sniffing provided before the thread sniffer is created
            sniffers.remove(&sniffing_state.interface_name.as_ref().unwrap().to_string());
        }
    }

    if stop {
        let mut exchanged_packets = state.exchanged_packets.lock().unwrap();
        std::mem::take(&mut *exchanged_packets);
    }
    cleanup_sniffing_state();

    info!("[{}] Sniffing stopped", interface_name);

    Ok(())
}

#[tauri::command]
fn generate_report(
    state: tauri::State<SniffingState>,
    report_path: String,
    first_generation: bool,
) -> Result<bool, SniffingError> {
    let mut exchanged_packets = state.exchanged_packets.lock().unwrap();
    let mut packets = std::mem::take(&mut *exchanged_packets);

    write_report(&report_path, &mut packets, first_generation).map_err(|e| {
        SniffingError::ReportGenerationFailed(format!("Report generation failed: {}", e))
    })
}

fn main() {
    dotenv::dotenv().ok();
    if !cfg!(target_os = "windows") {
        // sudo::escalate_if_needed();
    }

    let mut builder = Builder::from_default_env();
    builder
        .format(|buf, r| {
            writeln!(
                buf,
                "[{}] {}",
                buf.default_styled_level(r.level()),
                r.args()
            )
        })
        .init();

    tauri::Builder::default()
        .manage(SniffingState::new())
        .invoke_handler(tauri::generate_handler![
            start_sniffing,
            stop_sniffing,
            get_interfaces_list,
            generate_report,
            select_interface,
            get_packets,
        ])
        .run(tauri::generate_context!())
        .expect("Error while running tauri application");
}

// - Select interface
//   - Inexistent
// - Start sniffing
//   - Without prior selection of the interface
//   - (?) Unhandled channel type
//   - (?) Failed channel creation
//   - Empty interface
// - Re-Start sniffing
//   - Same interface
//   - Another interface never selected
//   - Another interface selected previously
// - Stop Sniffing
//   - Without prior starting of the process
// - Generate report
//   - Generation failed
