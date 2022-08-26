pub mod network;
pub mod transport;

use pnet::packet::Packet;
use pnet::{packet::ethernet::EthernetPacket, util::MacAddr};
use serde::Serialize;

pub trait SerializablePacket: erased_serde::Serialize {}
erased_serde::serialize_trait_object!(SerializablePacket);

#[derive(Serialize, Debug)]
pub struct SerializableEthernetPacket {
    destination: MacAddr,
    source: MacAddr,
    ethertype: String,
    payload: Vec<u8>,
}

impl SerializablePacket for SerializableEthernetPacket {}

impl<'a> From<&EthernetPacket<'a>> for SerializableEthernetPacket {
    fn from(packet: &EthernetPacket<'a>) -> Self {
        SerializableEthernetPacket {
            destination: packet.get_destination(),
            source: packet.get_source(),
            ethertype: packet.get_ethertype().to_string(),
            payload: packet.payload().to_vec(),
        }
    }
}
