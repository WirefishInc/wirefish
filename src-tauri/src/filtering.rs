use std::{collections::BTreeMap, sync::Arc};

use sniffer_parser::serializable_packet::ParsedPacket;

use crate::{SniffingError, SniffingState};

pub struct PacketsCollection {
    pub packets: Vec<Arc<ParsedPacket>>,
    pub source_ip_index: BTreeMap<String, Vec<Arc<ParsedPacket>>>,
}

impl PacketsCollection {
    pub fn new() -> Self {
        PacketsCollection {
            packets: vec![],
            source_ip_index: BTreeMap::new(),
        }
    }
}

fn get_slice<'a>(
    packets: &'a Vec<Arc<ParsedPacket>>,
    start: usize,
    end: usize,
) -> &'a [Arc<ParsedPacket>] {
    match packets.get(start..end) {
        Some(values) => values,
        None => packets.get(start..).unwrap(),
    }
}

#[tauri::command]
pub fn get_packets(
    start: usize,
    end: usize,
    state: tauri::State<SniffingState>,
) -> Result<Vec<ParsedPacket>, SniffingError> {
    let packets_collection = state.packets.lock().unwrap();

    if start > packets_collection.packets.len() {
        return Err(SniffingError::GetPacketsIndexNotValid(
            "The indexes are not valid".to_owned(),
        ));
    }

    return Ok(get_slice(&packets_collection.packets, start, end)
        .iter()
        .map(|x| ParsedPacket::clone(&*x))
        .collect::<Vec<ParsedPacket>>());
}

#[tauri::command]
pub fn filter_by_source_ip(
    source_ip: String,
    start: usize,
    end: usize,
    state: tauri::State<SniffingState>,
) -> Result<Vec<ParsedPacket>, SniffingError> {
    let packets_collection = state.packets.lock().unwrap();

    if start > packets_collection.packets.len() {
        return Err(SniffingError::GetPacketsIndexNotValid(
            "The indexes are not valid".to_owned(),
        ));
    }

    let slice = match packets_collection.source_ip_index.get(&source_ip) {
        Some(values) => get_slice(values, start, end),
        None => packets_collection.packets.get(start..).unwrap(),
    };

    return Ok(slice
        .iter()
        .map(|x| ParsedPacket::clone(&*x))
        .collect::<Vec<ParsedPacket>>());
}
