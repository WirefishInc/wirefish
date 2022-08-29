extern crate pnet;
extern crate sniffer_parser;

use dotenv;
use log::{error, info};

use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, DataLinkReceiver, NetworkInterface};
use pnet::packet::ethernet::EthernetPacket;

use std::sync::Arc;
use tauri::async_runtime::Mutex;
use tauri::{async_runtime, Manager, Window, Wry};
use tauri_awesome_rpc::{AwesomeEmit, AwesomeRpc};

use sniffer_parser::parse_ethernet_frame;

struct SniffingInfoState(Arc<Mutex<SniffingInfo>>);
struct SniffingInfo {
    interface_channel: Option<Box<dyn DataLinkReceiver>>,
    interface_name: Option<String>,
    is_sniffing: bool,
}

impl SniffingInfo {
    fn new() -> Self {
        SniffingInfo {
            interface_channel: None,
            interface_name: None,
            is_sniffing: false,
        }
    }
}

#[tauri::command]
async fn get_interfaces_list() -> Vec<String> {
    let interfaces = datalink::interfaces()
        .into_iter()
        .map(|i| i.description)
        .collect::<Vec<String>>();
    info!("Interfaces retrieved: {:#?}", interfaces);

    interfaces
}

#[tauri::command]
async fn select_interface(
    state: tauri::State<'_, SniffingInfoState>,
    interface_name: String,
) -> Result<(), ()> {
    let interface_names_match = |iface: &NetworkInterface| iface.description == interface_name;

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap();

    info!("Interface selected: {}", interface_name);

    // Create a new channel, dealing with layer 2 packets
    let (_, rx) = match datalink::channel(&interface, Default::default()) {
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

            drop(sniffing_state);
        }
    });

    Ok(())
}

#[tauri::command]
async fn stop_sniffing(state: tauri::State<'_, SniffingInfoState>) -> Result<(), ()> {
    let mut sniffing_state = state.0.lock().await;
    sniffing_state.is_sniffing = false;
    info!(
        "[{}] Sniffing stopped",
        sniffing_state.interface_name.as_ref().unwrap()
    );

    Ok(())
}

fn main() {
    dotenv::dotenv().ok();
    env_logger::init();

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
            select_interface
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
