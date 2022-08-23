extern crate pnet;

use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, DataLinkReceiver, DataLinkSender, NetworkInterface};
use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::EtherTypes::{Ipv4, Ipv6};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::icmp::{echo_reply, echo_request, IcmpPacket, IcmpTypes};
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::{MutablePacket, Packet};

use pnet::util::MacAddr;
use serde_json::json;
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use tauri::{Manager, State, Window, Wry};
use tauri_awesome_rpc::{AwesomeEmit, AwesomeRpc};

struct SniffingState {
    interface_channel: Arc<Mutex<Option<(bool, Box<dyn DataLinkReceiver>)>>>,
}

impl SniffingState {
    fn new() -> Self {
        SniffingState {
            interface_channel: Arc::new(Mutex::new(None)),
        }
    }
}

// JSON Packet fields:
// - Type (TCP, UDP, ...)
// - MAC Source
// - MAC Destination
// - IP Source
// - IP Destination
// - Length
// - (?) Info
// - (?) Payload

fn handle_udp_packet(
    mac_source: MacAddr,
    mac_destination: MacAddr,
    source: IpAddr,
    destination: IpAddr,
    packet: &[u8],
    window: &Window<Wry>,
) {
    let udp = UdpPacket::new(packet);

    if let Some(udp) = udp {
        println!(
            "[]: UDP Packet: {}:{} > {}:{}; length: {}",
            source,
            udp.get_source(),
            destination,
            udp.get_destination(),
            udp.get_length()
        );

        window.state::<AwesomeEmit>().emit(
            "main",
            "packet_received",
            serde_json::to_string(&(
                "UDP",
                mac_source,
                mac_destination,
                format!("{}:{}", source, udp.get_source()),
                format!("{}:{}", destination, udp.get_destination()),
                udp.get_length(),
                "-",
            ))
            .unwrap(),
        )
    } else {
        println!("[]: Malformed UDP Packet");
    }
}

fn handle_icmp_packet(
    mac_source: MacAddr,
    mac_destination: MacAddr,
    source: IpAddr,
    destination: IpAddr,
    packet: &[u8],
    window: &Window<Wry>,
) {
    let icmp_packet = IcmpPacket::new(packet);
    if let Some(icmp_packet) = icmp_packet {
        match icmp_packet.get_icmp_type() {
            IcmpTypes::EchoReply => {
                let echo_reply_packet = echo_reply::EchoReplyPacket::new(packet).unwrap();
                println!(
                    "[]: ICMP echo reply {} -> {} (seq={:?}, id={:?})",
                    source,
                    destination,
                    echo_reply_packet.get_sequence_number(),
                    echo_reply_packet.get_identifier()
                );

                window.state::<AwesomeEmit>().emit(
                    "main",
                    "packet_received",
                    serde_json::to_string(&(
                        "ICMP echo reply",
                        mac_source,
                        mac_destination,
                        source,
                        destination,
                        packet.len(),
                        format!(
                            "seq={:?}, id={:?}",
                            echo_reply_packet.get_sequence_number(),
                            echo_reply_packet.get_identifier()
                        ),
                    ))
                    .unwrap(),
                )
            }
            IcmpTypes::EchoRequest => {
                let echo_request_packet = echo_request::EchoRequestPacket::new(packet).unwrap();
                println!(
                    "[]: ICMP echo request {} -> {} (seq={:?}, id={:?})",
                    source,
                    destination,
                    echo_request_packet.get_sequence_number(),
                    echo_request_packet.get_identifier()
                );

                window.state::<AwesomeEmit>().emit(
                    "main",
                    "packet_received",
                    serde_json::to_string(&(
                        "ICMP echo request",
                        mac_source,
                        mac_destination,
                        source,
                        destination,
                        packet.len(),
                        format!(
                            "seq={:?}, id={:?}",
                            echo_request_packet.get_sequence_number(),
                            echo_request_packet.get_identifier()
                        ),
                    ))
                    .unwrap(),
                )
            }
            _ => {
                println!(
                    "[]: ICMP packet {} -> {} (code={:?}, type={:?})",
                    source,
                    destination,
                    icmp_packet.get_icmp_code(),
                    icmp_packet.get_icmp_type()
                );

                window.state::<AwesomeEmit>().emit(
                    "main",
                    "packet_received",
                    serde_json::to_string(&(
                        "ICMP-V6",
                        mac_source,
                        mac_destination,
                        source,
                        destination,
                        packet.len(),
                        format!(
                            "code={:?}, type={:?}",
                            icmp_packet.get_icmp_code(),
                            icmp_packet.get_icmp_type()
                        ),
                    ))
                    .unwrap(),
                )
            }
        }
    } else {
        println!("[]: Malformed ICMP Packet");
    }
}

fn handle_icmpv6_packet(
    mac_source: MacAddr,
    mac_destination: MacAddr,
    source: IpAddr,
    destination: IpAddr,
    packet: &[u8],
    window: &Window<Wry>,
) {
    let icmpv6_packet = Icmpv6Packet::new(packet);
    if let Some(icmpv6_packet) = icmpv6_packet {
        println!(
            "[]: ICMPv6 packet {} -> {} (type={:?})",
            source,
            destination,
            icmpv6_packet.get_icmpv6_type()
        );

        window.state::<AwesomeEmit>().emit(
            "main",
            "packet_received",
            serde_json::to_string(&(
                "ICMP-V6",
                mac_source,
                mac_destination,
                source,
                destination,
                packet.len(),
                format!(
                    "code={:?}, type={:?}",
                    icmpv6_packet.get_icmpv6_code(),
                    icmpv6_packet.get_icmpv6_type()
                ),
            ))
            .unwrap(),
        )
    } else {
        println!("[]: Malformed ICMPv6 Packet");
    }
}

fn handle_tcp_packet(
    mac_source: MacAddr,
    mac_destination: MacAddr,
    source: IpAddr,
    destination: IpAddr,
    packet: &[u8],
    window: &Window<Wry>,
) {
    let tcp = TcpPacket::new(packet);
    if let Some(tcp) = tcp {
        println!(
            "[]: TCP Packet: {}:{} > {}:{}; length: {}",
            source,
            tcp.get_source(),
            destination,
            tcp.get_destination(),
            packet.len()
        );

        window.state::<AwesomeEmit>().emit(
            "main",
            "packet_received",
            serde_json::to_string(&(
                "TCP",
                mac_source,
                mac_destination,
                format!("{}:{}", source, tcp.get_source()),
                format!("{}:{}", destination, tcp.get_destination()),
                packet.len(),
                "-",
            ))
            .unwrap(),
        )
    } else {
        println!("[]: Malformed TCP Packet");
    }
}

fn handle_transport_protocol(
    mac_source: MacAddr,
    mac_destination: MacAddr,
    source: IpAddr,
    destination: IpAddr,
    protocol: IpNextHeaderProtocol,
    packet: &[u8],
    window: &Window<Wry>,
) {
    match protocol {
        IpNextHeaderProtocols::Udp => handle_udp_packet(
            mac_source,
            mac_destination,
            source,
            destination,
            packet,
            window,
        ),
        IpNextHeaderProtocols::Tcp => handle_tcp_packet(
            mac_source,
            mac_destination,
            source,
            destination,
            packet,
            window,
        ),
        IpNextHeaderProtocols::Icmp => handle_icmp_packet(
            mac_source,
            mac_destination,
            source,
            destination,
            packet,
            window,
        ),
        IpNextHeaderProtocols::Icmpv6 => handle_icmpv6_packet(
            mac_source,
            mac_destination,
            source,
            destination,
            packet,
            window,
        ),
        _ => println!(
            "[]: Unknown {} packet: {} > {}; protocol: {:?} length: {}",
            match source {
                IpAddr::V4(..) => "IPv4",
                _ => "IPv6",
            },
            source,
            destination,
            protocol,
            packet.len()
        ),
    }
}

fn handle_ipv4_packet(ethernet: &EthernetPacket, window: &Window<Wry>) {
    let header = Ipv4Packet::new(ethernet.payload());
    if let Some(header) = header {
        handle_transport_protocol(
            ethernet.get_source(),
            ethernet.get_destination(),
            IpAddr::V4(header.get_source()),
            IpAddr::V4(header.get_destination()),
            header.get_next_level_protocol(),
            header.payload(),
            window,
        );
    } else {
        println!("[]: Malformed IPv4 Packet");
    }
}

fn handle_ipv6_packet(ethernet: &EthernetPacket, window: &Window<Wry>) {
    let header = Ipv6Packet::new(ethernet.payload());
    if let Some(header) = header {
        handle_transport_protocol(
            ethernet.get_source(),
            ethernet.get_destination(),
            IpAddr::V6(header.get_source()),
            IpAddr::V6(header.get_destination()),
            header.get_next_header(),
            header.payload(),
            window,
        );
    } else {
        println!("[]: Malformed IPv6 Packet");
    }
}

fn handle_arp_packet(ethernet: &EthernetPacket, window: &Window<Wry>) {
    let header = ArpPacket::new(ethernet.payload());
    if let Some(header) = header {
        println!(
            "[]: ARP packet: {}({}) > {}({}); operation: {:?}",
            ethernet.get_source(),
            header.get_sender_proto_addr(),
            ethernet.get_destination(),
            header.get_target_proto_addr(),
            header.get_operation()
        );

        window.state::<AwesomeEmit>().emit(
            "main",
            "packet_received",
            serde_json::to_string(&(
                "ARP",
                ethernet.get_source(),
                ethernet.get_destination(),
                header.get_sender_proto_addr(),
                header.get_target_proto_addr(),
                ethernet.payload().len(),
                "-",
            ))
            .unwrap(),
        )
    } else {
        println!("[]: Malformed ARP Packet");
    }
}

fn handle_ethernet_frame(ethernet: &EthernetPacket, window: &Window<Wry>) {
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => handle_ipv4_packet(ethernet, window),
        EtherTypes::Ipv6 => handle_ipv6_packet(ethernet, window),
        EtherTypes::Arp => handle_arp_packet(ethernet, window),
        _ => println!(
            "[]: Unknown packet: {} > {}; ethertype: {:?} length: {}",
            ethernet.get_source(),
            ethernet.get_destination(),
            ethernet.get_ethertype(),
            ethernet.packet().len()
        ),
    }
}

#[tauri::command]
fn get_interfaces_list() -> Vec<String> {
    println!("Interface retrieval started");
    let interfaces = datalink::interfaces()
        .into_iter()
        .map(|i| i.description)
        .collect::<Vec<String>>();
    println!("Interfaces: {:?}", interfaces);
    interfaces
}

#[tauri::command]
fn select_interface(state: tauri::State<SniffingState>, interface_name: String) {
    println!("Interface name: {}", interface_name);

    let interface_names_match = |iface: &NetworkInterface| iface.description == interface_name;

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap();

    // Create a new channel, dealing with layer 2 packets
    let (tx, rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!(
            "An error occurred when creating the datalink channel: {}",
            e
        ),
    };

    let mut interface_channel = state.interface_channel.lock().expect("Poisoned lock");
    *interface_channel = Some((false, rx));

    println!("Selected!");
}

#[tauri::command]
fn start_sniffing(state: tauri::State<SniffingState>, window: Window<Wry>) {
    // Set sniffing to true
    state
        .interface_channel
        .lock()
        .expect("Poisoned lock")
        .as_mut()
        .unwrap()
        .0 = true;

    let channel = Arc::clone(&state.interface_channel);
    std::thread::spawn(move || {
        let mut buf: [u8; 64_000] = [0u8; 64_000];

        loop {
            let mut channel = channel.lock().expect("Poisoned lock");
            if channel.as_mut().is_none() || !channel.as_mut().unwrap().0 {
                break;
            }

            match channel.as_mut().unwrap().1.next() {
                Ok(packet) => handle_ethernet_frame(&EthernetPacket::new(packet).unwrap(), &window),
                Err(e) => {
                    // If an error occurs, we can handle it here
                    panic!("An error occurred while reading: {}", e);
                }
            }

            drop(channel);
        }
    });
}

#[tauri::command]
fn stop_sniffing(state: tauri::State<SniffingState>) {
    let mut channel = state.interface_channel.lock().expect("Poisoned lock");
    channel.as_mut().unwrap().0 = false;
    println!("Stop Sniffing :(");
}

fn main() {
    let awesome_rpc = AwesomeRpc::new(vec!["tauri://localhost", "http://localhost:*"]);

    tauri::Builder::default()
        .invoke_system(awesome_rpc.initialization_script(), AwesomeRpc::responder())
        .setup(move |app| {
            awesome_rpc.start(app.handle());
            Ok(())
        })
        .manage(SniffingState::new())
        .invoke_handler(tauri::generate_handler![
            start_sniffing,
            stop_sniffing,
            get_interfaces_list,
            select_interface
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
