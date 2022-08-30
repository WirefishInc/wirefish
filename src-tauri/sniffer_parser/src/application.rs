use std::{cell::RefCell, collections::HashMap, net::IpAddr};

use crate::serializable_packet::application::{
    SerializableHttpRequestPacket, SerializableHttpResponsePacket,
};
use crate::serializable_packet::ParsedPacket;
use crate::SerializablePacket;

pub enum HttpType {
    Request,
    Response,
}

pub const HTTP_PORT: u16 = 80;

thread_local!(
    static ACTIVE_PARSERS: RefCell<HashMap<((IpAddr, u16), (IpAddr, u16)), Vec<u8>>>
        = RefCell::new(HashMap::new())
);

pub fn handle_http_packet(
    source_ip: IpAddr,
    source_port: u16,
    dest_ip: IpAddr,
    dest_port: u16,
    http_type: HttpType,
    packet: &[u8],
    parsed_packet: &mut ParsedPacket,
) {
    ACTIVE_PARSERS.with(|parsers| {
        let mut parsers = parsers.borrow_mut();
        let current_payload = parsers
            .entry(((source_ip, source_port), (dest_ip, dest_port)))
            .and_modify(|payload| payload.append(packet.to_vec().as_mut()))
            .or_insert(vec![]);

        let mut headers = [httparse::EMPTY_HEADER; 64];

        match http_type {
            HttpType::Request => {
                let mut request = httparse::Request::new(&mut headers);
                let status = request.parse(current_payload);

                if let Ok(status) = status {
                    if status.is_complete() {
                        println!(
                            "[]: HTTP Request Packet: {:?} {:?} {:?}; Headers: {:?}",
                            request.method, request.path, request.version, request.headers,
                        );

                        parsed_packet.set_application_layer_packet(Some(
                            SerializablePacket::HttpRequestPacket(
                                SerializableHttpRequestPacket::from(&request),
                            ),
                        ));

                        parsers.remove(&((source_ip, source_port), (dest_ip, dest_port)));
                    }
                }
            }
            HttpType::Response => {
                let mut response = httparse::Response::new(&mut headers);
                let status = response.parse(current_payload);

                if let Ok(status) = status {
                    if status.is_complete() {
                        println!(
                            "[]: HTTP Response Packet: {:?} {:?} {:?}; Headers: {:?}",
                            response.version, response.code, response.reason, response.headers
                        );

                        parsed_packet.set_application_layer_packet(Some(
                            SerializablePacket::HttpResponsePacket(
                                SerializableHttpResponsePacket::from(&response),
                            ),
                        ));

                        parsers.remove(&((source_ip, source_port), (dest_ip, dest_port)));
                    }
                }
            }
        }
    });
}
