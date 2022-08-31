use std::str::from_utf8;
use std::{cell::RefCell, collections::HashMap, net::IpAddr};

use mime::Mime;

use crate::serializable_packet::application::{
    HttpContentType, SerializableHttpRequestPacket, SerializableHttpResponsePacket,
};
use crate::serializable_packet::ParsedPacket;
use crate::SerializablePacket;

const CONTENT_TYPE: &str = "Content-Type";

pub enum HttpPacketType {
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
    http_type: HttpPacketType,
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
            HttpPacketType::Request => {
                let mut request = httparse::Request::new(&mut headers);
                let status = request.parse(current_payload);

                if let Ok(status) = status {
                    if status.is_complete() {
                        let mut parsed_payload = HttpContentType::None;

                        if !current_payload[status.unwrap()..].is_empty() {
                            parsed_payload = parse_http_payload(
                                &current_payload[status.unwrap()..],
                                request
                                    .headers
                                    .iter()
                                    .find(|h| h.name == CONTENT_TYPE)
                                    .and_then(|h| from_utf8(h.value).unwrap().parse::<Mime>().ok()),
                            );
                        }

                        println!(
                            "[]: HTTP Request Packet: {:?} {:?} {:?}; Headers: {:?}; Payload: {:?}",
                            request.method, request.path, request.version, request.headers, parsed_payload
                        );

                        parsed_packet.set_application_layer_packet(Some(
                            SerializablePacket::HttpRequestPacket(
                                SerializableHttpRequestPacket::new(&request, parsed_payload),
                            ),
                        ));

                        parsers.remove(&((source_ip, source_port), (dest_ip, dest_port)));
                    }
                }
            }
            HttpPacketType::Response => {
                let mut response = httparse::Response::new(&mut headers);
                let status = response.parse(current_payload);

                if let Ok(status) = status {
                    if status.is_complete() {
                        let mut parsed_payload = HttpContentType::None;

                        if !current_payload[status.unwrap()..].is_empty() {
                            parsed_payload = parse_http_payload(
                                &current_payload[status.unwrap()..],
                                response
                                    .headers
                                    .iter()
                                    .find(|h| h.name == CONTENT_TYPE)
                                    .and_then(|h| from_utf8(h.value).unwrap().parse::<Mime>().ok()),
                            );
                        }

                        println!(
                            "[]: HTTP Response Packet: {:?} {:?} {:?}; Headers: {:?}; Payload: {:?}",
                            response.version, response.code, response.reason, response.headers, parsed_payload
                        );

                        parsed_packet.set_application_layer_packet(Some(
                            SerializablePacket::HttpResponsePacket(
                                SerializableHttpResponsePacket::new(&response, parsed_payload),
                            ),
                        ));

                        parsers.remove(&((source_ip, source_port), (dest_ip, dest_port)));
                    }
                }
            }
        }
    });
}

fn parse_http_payload(payload: &[u8], mime: Option<Mime>) -> HttpContentType {
    if mime.is_none() {
        return HttpContentType::Unknown(payload.to_vec());
    }

    let mime = mime.unwrap();
    return match (mime.type_(), mime.subtype()) {
        (mime::TEXT, _) => match from_utf8(payload) {
            Ok(string) => HttpContentType::Text(string.to_owned()),
            _ => HttpContentType::Unknown(payload.to_vec()),
        },
        (mime::IMAGE, _) => HttpContentType::Image(payload.to_vec()),
        _ => HttpContentType::Unknown(payload.to_vec()),
    };
}
