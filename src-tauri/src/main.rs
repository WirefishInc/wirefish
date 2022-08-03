#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

extern crate pnet;

use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, DataLinkReceiver, DataLinkSender, NetworkInterface};
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};

use serde_json::json;
use std::fmt::{Display, Formatter};
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

#[tauri::command]
fn get_interfaces_list() -> Vec<String> {
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
    state.interface_channel.lock().expect("Poisoned lock").as_mut().unwrap().0 = true;
    
    let channel = Arc::clone(&state.interface_channel);
    std::thread::spawn(move || {
        let mut buf: [u8; 64_000] = [0u8; 64_000];

        loop {
            let mut channel = channel.lock().expect("Poisoned lock");
            if channel.as_mut().is_none() || !channel.as_mut().unwrap().0 { break; }

            match channel.as_mut().unwrap().1.next() {
                Ok(packet) => {
                    let packet = EthernetPacket::new(packet).unwrap();
                    let mut new_packet = MutableEthernetPacket::new(&mut buf[..]).unwrap();

                    // Create a clone of the original packet
                    new_packet.clone_from(&packet);

                    window.state::<AwesomeEmit>().emit(
                        "main",
                        "packet_received",
                        serde_json::to_string(&(
                            new_packet.get_source(),
                            new_packet.get_destination(),
                        ))
                        .unwrap(),
                    )
                }
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
