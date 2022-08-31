use std::str::from_utf8;

use httparse::{Request, Response};
use serde::Serialize;

#[derive(Serialize, Debug)]
pub enum HttpContentType {
    Text(String),
    Image(Vec<u8>),
    Unknown(Vec<u8>),
    None
}

/// HTTP Request Packet Representation

#[derive(Serialize, Debug)]
pub struct SerializableHttpRequestPacket {
    pub method: String,
    pub path: String,
    pub version: u8,
    pub headers: Vec<(String, String)>,
    pub payload: HttpContentType,
}

impl<'a, 'b> SerializableHttpRequestPacket {
    pub fn new(packet: &Request<'a, 'b>, payload: HttpContentType) -> Self {
        SerializableHttpRequestPacket {
            method: packet.method.unwrap().to_owned(),
            path: packet.path.unwrap().to_owned(),
            version: packet.version.unwrap(),
            headers: packet
                .headers
                .iter()
                .map(|header| {
                    (
                        header.name.to_string(),
                        from_utf8(header.value)
                            .unwrap_or("Not valid UTF8")
                            .to_owned(),
                    )
                })
                .collect(),
            payload,
        }
    }
}

/// HTTP Response Packet Representation

#[derive(Serialize, Debug)]
pub struct SerializableHttpResponsePacket {
    pub version: u8,
    pub code: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub payload: HttpContentType,
}

impl<'a, 'b> SerializableHttpResponsePacket {
    pub fn new(packet: &Response<'a, 'b>, payload: HttpContentType) -> Self {
        SerializableHttpResponsePacket {
            version: packet.version.unwrap(),
            code: packet.code.unwrap(),
            reason: packet.reason.unwrap().to_owned(),
            headers: packet
                .headers
                .iter()
                .map(|header| {
                    (
                        header.name.to_string(),
                        from_utf8(header.value)
                            .unwrap_or("Not valid UTF8")
                            .to_owned(),
                    )
                })
                .collect(),
            payload,
        }
    }
}
