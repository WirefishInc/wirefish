use std::{io::Read, net::IpAddr};

use encoding_rs::Encoding;
use flate2::bufread::{DeflateDecoder, GzDecoder, ZlibDecoder};
use httparse::Header;
use log::debug;
use mime::Mime;

use crate::{
    serializable_packet::{
        application::{
            HttpContentType, SerializableHttpRequestPacket, SerializableHttpResponsePacket,
        },
        ParsedPacket, SerializablePacket,
    },
    HttpPacketType, ACTIVE_HTTP_PARSERS,
};

use super::{ContentEncoding, HeaderNamesValues};

#[derive(Debug)]
enum HttpParsingError {
    TransferEncodingMalformed(String),
    DecodingPayloadFailed(String, String),
    UnknownDecodingAlgorithm(String, String),
    Other,
}

type Result<T> = std::result::Result<T, HttpParsingError>;

pub fn handle_http_packet(
    source_ip: IpAddr,
    source_port: u16,
    dest_ip: IpAddr,
    dest_port: u16,
    http_type: HttpPacketType,
    is_fin: bool,
    packet: &[u8],
    parsed_packet: &mut ParsedPacket,
) {
    ACTIVE_HTTP_PARSERS.with(|parsers| {
        let mut parsers = parsers.borrow_mut();
        let current_payload = parsers
            .entry(((source_ip, source_port), (dest_ip, dest_port)))
            .and_modify(|payload| payload.append(packet.to_vec().as_mut()))
            .or_insert(packet.to_vec());

        let mut headers = [httparse::EMPTY_HEADER; 1024];

        match http_type {
            HttpPacketType::Request => {
                let mut request = httparse::Request::new(&mut headers);
                let status = request.parse(&current_payload);

                if let Ok(status) = status {
                    if status.is_complete() {
                        let start = status.unwrap();
                        let current_payload_size = current_payload.len() - start;

                        if packet_is_ended(&current_payload[start..], current_payload_size,
                            request.headers, http_type, is_fin)
                        {
                            let parsed_payload = parse_http_payload(
                                current_payload.clone(),
                                start,
                                request.headers,
                            );

                            match parsed_payload {
                                Ok(parsed_payload) => {
                                    debug!(
                                        "HTTP Request Packet: {:?} {:?} {:?}; Headers: {:?}; Payload: {:?}",
                                        request.method, request.path, request.version, request.headers, parsed_payload
                                    );

                                    parsed_packet.set_application_layer_packet(Some(
                                        SerializablePacket::HttpRequestPacket(
                                            SerializableHttpRequestPacket::new(&request, parsed_payload),
                                        ),
                                    ));
                                },
                                Err(_) => {
                                    debug!("Malformed HTTP Request Packet");
                                    parsed_packet.set_network_layer_packet(Some(SerializablePacket::MalformedPacket(
                                        "Malformed HTTP Request Packet".to_string(),
                                    )));
                                }
                            }

                            parsers.remove(&((source_ip, source_port), (dest_ip, dest_port)));

                        }
                    }
                }
            }
            HttpPacketType::Response => {
                let mut response = httparse::Response::new(&mut headers);
                let status = response.parse(current_payload);

                if let Ok(status) = status {
                    if status.is_complete() {
                        let start = status.unwrap();
                        let current_payload_size = current_payload.len() - start;

                        if packet_is_ended(&current_payload[start..], current_payload_size,
                            response.headers, http_type, is_fin)
                        {
                            let parsed_payload = parse_http_payload(
                                current_payload.clone(),
                                start,
                                response.headers,
                            );

                            match parsed_payload {
                                Ok(parsed_payload) => {
                                    debug!(
                                        "HTTP Response Packet: {:?} {:?} {:?}; Headers: {:?}; Payload: {:?}",
                                        response.version, response.code, response.reason, response.headers, parsed_payload
                                    );

                                    parsed_packet.set_application_layer_packet(Some(
                                        SerializablePacket::HttpResponsePacket(
                                            SerializableHttpResponsePacket::new(&response, parsed_payload),
                                        ),
                                    ));
                                },
                                Err(_) => {
                                    debug!("Malformed HTTP Response Packet");
                                    parsed_packet.set_network_layer_packet(Some(SerializablePacket::MalformedPacket(
                                        "Malformed HTTP Response Packet".to_string(),
                                    )));
                                }
                            }

                            parsers.remove(&((source_ip, source_port), (dest_ip, dest_port)));
                        }
                    }
                }
            }
        }
    });
}

// We can say thay an HTTP Request is ended when one the following is true:
// 1. The Request/Response contains the `Content-Length` header and the number of bytes accumulated is the same
// 2. The Request/Response contains the `Transfer-Encoding: chunked` and the last chunk has arrived. THe last chunk
//    it's empty and preceded by a `0` lenght indication.
// 3. The server closes the connection when the Request/Response has been transmitted (FIN-ACK at Transport level)

fn packet_is_ended(
    payload: &[u8],
    current_payload_size: usize,
    headers: &mut [Header],
    http_type: HttpPacketType,
    is_fin_set: bool,
) -> bool {
    let length = get_header_value(HeaderNamesValues::CONTENT_LENGTH, headers);
    let transfer_encoding = get_header_value(HeaderNamesValues::TRANSFER_ENCODING, headers);

    if length.is_none() && transfer_encoding.is_none() {
        return match http_type {
            HttpPacketType::Request => true,
            HttpPacketType::Response => is_fin_set,
        };
    }

    // If Content-Length is equal
    if length.is_some() && current_payload_size == length.unwrap().parse::<usize>().unwrap() {
        return true;
    }

    // If Transfer-Encoding is chuncked and last chunck arrived
    if transfer_encoding.is_some() && transfer_encoding.unwrap() == HeaderNamesValues::CHUNKED {
        let last_bytes = payload.into_iter().rev().take(5).collect::<Vec<&u8>>();
        let mut i = 0;

        while i < last_bytes.len() {
            let seq = "\n\r\n\r0".as_bytes().get(i);
            let pay = last_bytes.get(i);

            if seq.is_none() || pay.is_none() || seq.unwrap() != *pay.unwrap() {
                break;
            }

            i += 1;
        }

        println!("{} {}", i, last_bytes.len());

        if i == last_bytes.len() {
            return true;
        }
    }

    false
}

fn parse_http_payload(
    payload_with_headers: Vec<u8>,
    start: usize,
    headers: &mut [Header],
) -> Result<HttpContentType> {
    let mut payload = payload_with_headers[start..].to_vec();
    if payload.is_empty() {
        return Ok(HttpContentType::None);
    }

    let transfer_encoding = get_header_value(HeaderNamesValues::TRANSFER_ENCODING, headers);
    if transfer_encoding.is_some() && transfer_encoding.unwrap() == HeaderNamesValues::CHUNKED {
        payload = merge_chunks(payload)?;
    }

    let mime = get_header_value(HeaderNamesValues::CONTENT_TYPE, headers);
    if mime.is_none() {
        return Ok(HttpContentType::Unknown(payload));
    }
    let mime = mime.unwrap().parse::<Mime>();
    if mime.is_err() {
        return Ok(HttpContentType::Unknown(payload));
    }

    let mime = mime.unwrap();
    let encoding = get_header_value(HeaderNamesValues::CONTENT_ENCODING, headers);

    return match encoding {
        Some(encoding) => {
            let result = decode_payload(&mut payload, encoding);
            return match result {
                Ok(decoded_payload) => Ok(get_http_type(mime, decoded_payload.to_vec(), None)),
                Err(algo) => match algo {
                    HttpParsingError::DecodingPayloadFailed(algo, _) => {
                        Ok(get_http_type(mime, payload.to_vec(), Some(&algo)))
                    }
                    HttpParsingError::UnknownDecodingAlgorithm(algo, _) => {
                        Ok(get_http_type(mime, payload.to_vec(), Some(&algo)))
                    }
                    _ => Err(HttpParsingError::Other),
                },
            };
        }
        None => Ok(get_http_type(mime, payload.to_vec(), None)),
    };
}

fn merge_chunks(payload: Vec<u8>) -> Result<Vec<u8>> {
    let mut merged = vec![];
    let mut index = 0;
    let mut length = "".to_owned();

    loop {
        length.clear();
        loop {
            if payload[index] == b"\r"[0] && payload[index + 1] == b"\n"[0] {
                break;
            }

            if !payload[index].is_ascii_hexdigit() {
                return Err(HttpParsingError::TransferEncodingMalformed(
                    format!(
                        "Malformed Transfer-Encoding HTTP Packet: chunk's length not valid Hexadecimal character (\\x{})",
                        payload[index]
                    ),
                ));
            }

            length.push(char::from_u32(payload[index] as u32).unwrap());
            index += 1;
        }

        let length = usize::from_str_radix(&length, 16).unwrap();
        println!("Length: {}", length);

        // Skip \r\n
        index += 2;

        for _ in 0..length {
            merged.push(payload[index]);
            index += 1;
        }

        // Skip \r\n
        index += 2;

        // If last chunk
        let is_last_chunk = std::panic::catch_unwind(|| {
            if payload[index] == b"0"[0]
                && payload[index + 1] == b"\r"[0]
                && payload[index + 2] == b"\n"[0]
                && payload[index + 3] == b"\r"[0]
                && payload[index + 4] == b"\n"[0]
            {
                true
            } else {
                false
            }
        })
        .map_err(|_| {
            HttpParsingError::TransferEncodingMalformed(
                "Malformed Transfer-Encoding HTTP Packet: last chunk is too small".to_owned(),
            )
        });

        match is_last_chunk {
            Ok(true) => break,
            Err(err) => return Err(err),
            _ => (),
        }
    }

    Ok(merged)
}

fn get_header_value<'a, 'b>(name: &'a str, headers: &'b [Header]) -> Option<&'b str> {
    let header = headers.iter().find(|h| h.name == name);

    match header {
        Some(h) => std::str::from_utf8(h.value).ok(),
        None => None,
    }
}

fn get_http_type(mime: Mime, payload: Vec<u8>, encoding: Option<&str>) -> HttpContentType {
    return match (mime.type_(), mime.subtype()) {
        (_, _) if encoding.is_some() => {
            HttpContentType::Encoded(encoding.unwrap().to_string(), payload)
        }
        (mime::TEXT, _) => {
            let charset = mime.get_param(mime::CHARSET);

            if let Some(charset) = charset {
                let encoded = Encoding::for_label(charset.as_str().as_bytes());

                if let Some(encoded) = encoded {
                    let encoded = encoded.decode_with_bom_removal(payload.as_slice());

                    return match encoded {
                        (string, false) => {
                            HttpContentType::TextCorrectlyDecoded(string.to_string())
                        }
                        (string, true) => HttpContentType::TextMalformedDecoded(string.to_string()),
                    };
                }
            }

            HttpContentType::TextDefaultDecoded(String::from_utf8_lossy(&payload).to_string())
        }
        (mime::IMAGE, _) => HttpContentType::Image(payload.to_vec()),
        (mime::MULTIPART, _) => HttpContentType::Multipart(payload.to_vec()),
        _ => HttpContentType::Unknown(payload.to_vec()),
    };
}

fn decode_payload<'a>(payload: &mut Vec<u8>, encoding: &'a str) -> Result<Vec<u8>> {
    let mut extensions = encoding.split(", ").collect::<Vec<&str>>();
    extensions.reverse();

    let mut final_decoded = vec![];

    for ext in extensions {
        match ext {
            ContentEncoding::GZIP => {
                let mut decoder = GzDecoder::new(payload.as_slice());
                match decoder.read_to_end(&mut final_decoded) {
                    Err(_) => {
                        return Err(HttpParsingError::DecodingPayloadFailed(
                            ext.to_owned(),
                            format!("Decoding failed for: {ext}"),
                        ))
                    }
                    _ => (),
                }
            }
            ContentEncoding::ZLIB => {
                let mut decoder = ZlibDecoder::new(payload.as_slice());
                match decoder.read_to_end(&mut final_decoded) {
                    Err(_) => {
                        return Err(HttpParsingError::DecodingPayloadFailed(
                            ext.to_owned(),
                            format!("Decoding failed for: {ext}"),
                        ))
                    }
                    _ => (),
                }
            }
            ContentEncoding::DEFLATE => {
                let mut decoder = DeflateDecoder::new(payload.as_slice());
                match decoder.read_to_end(&mut final_decoded) {
                    Err(_) => {
                        return Err(HttpParsingError::DecodingPayloadFailed(
                            ext.to_owned(),
                            format!("Decoding failed for: {ext}"),
                        ))
                    }
                    _ => (),
                }
            }
            _ => {
                return Err(HttpParsingError::UnknownDecodingAlgorithm(
                    ext.to_owned(),
                    format!("Unknown algorithm: {ext}"),
                ))
            }
        }

        payload.clone_from(&final_decoded);
    }

    Ok(final_decoded)
}

// - X Packet ending
//   - X Ended by FIN-ACK
//   - X Ended by Content-Length
//   - X Ended by Transfer-Encoding chunked
// - Encoded payload
//   - GZIP
//   - ZLIB
//   - DEFLATE
//   - Unrecognized
//   - Wrongly Formatted (Decoding failed)
// - X Charset
//   - X Default charset (utf-8)
//   - X Provided charset
//     - X Existent
//     - X Inexistent
// - X Get Header
//   - X Existent
//   - X Inexistent
// - X Error Transfer-Encoding chunked
//   - X Last chunk not formatted correctly
//   - X Length not in hexadecimal

#[cfg(test)]
mod tests {
    use mime::Mime;
    use std::net::{IpAddr, Ipv4Addr};

    use super::{
        decode_payload, get_http_type, handle_http_packet, merge_chunks, packet_is_ended,
        HttpParsingError,
    };
    use crate::{
        application::{HeaderNamesValues, WellKnownPorts},
        http::get_header_value,
        serializable_packet::{application::HttpContentType, ParsedPacket, SerializablePacket},
        HttpPacketType,
    };

    const BASIC_REQUEST: &[u8] = b"GET / HTTP/1.1\r\n\r\n";
    const BASIC_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nDate: Sat, 10 Sep 2022 13:38:03 GMT\r\n\r\n";

    const CONTENT_LENGTH_ENDED_RESPONSE: &[u8] =
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nmiao\r\n\r\n";
    const CONTENT_LENGTH_ENDED_LENGTH: usize = 4;

    const CHUNKED_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
    4\r\nmiao\r\n0\r\n\r\n";
    const CHUNKED_RESPONSE_LENGTH: usize = 14;

    const CHUNKED_NOT_HEXA_RESPONSE : &str = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
    AR\r\nddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\
    ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\r\n0\r\n\r\n";
    const CHUNKED_NOT_HEXA_RESPONSE_LENGTH: usize = 181;

    const CHUNKED_LAST_CHUNK_NOT_ENDED_RESPONSE: &str =
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
    4\r\nmiao\r\n0\r\n";
    const CHUNKED_LAST_CHUNK_NOT_ENDED_RESPONSE_LENGTH: usize = 12;

    const DECODED_PAYLOAD: &[u8] = b"miao";
    const GZIP_ENCODED_RESPONSE : &[u8] = b"HTTP/1.1 404 Not Found\r\nContent-Length: 24\r\n\
    Content-Encoding: gzip\r\n\
    \x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xcb\xcd\x4c\xcc\x07\x00\x42\x26\xe5\x0e\x04\x00\x00\x00";
    const GZIP_ENCODED_RESPONSE_LENGTH: usize = 24;

    const ZLIB_ENCODED_RESPONSE: &[u8] = b"HTTP/1.1 404 Not Found\r\nContent-Length: 23\r\n\
    Content-Encoding: zlib\r\n\
    \x78\x9c\x05\xc0\x21\x0d\x00\x00\x00\x02\xb0\xac\x48\x04\xa3\xbf\xfb\xd6\x1c\x04\x24\x01\xa7";
    const ZLIB_ENCODED_RESPONSE_LENGTH: usize = 23;

    const DEFLATE_ENCODED_RESPONSE: &[u8] = b"HTTP/1.1 404 Not Found\r\nContent-Length: 17\r\n\
    Content-Encoding: deflate\r\n\
    \x05\xc0\x21\x0d\x00\x00\x00\x02\xb0\xac\x48\x04\xa3\xbf\xfb\xd6\x1c";
    const DEFLATE_ENCODED_RESPONSE_LENGTH: usize = 17;

    #[test]
    fn incomplete_header_http_packet() {
        let mut parsed_packet = ParsedPacket::new();
        handle_http_packet(
            IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10)),
            4444,
            IpAddr::V4(Ipv4Addr::new(11, 11, 11, 11)),
            WellKnownPorts::HTTP_PORT,
            HttpPacketType::Request,
            false,
            &BASIC_REQUEST[0..8],
            &mut parsed_packet,
        );

        assert!(parsed_packet.get_application_layer_packet().is_none());
    }

    #[test]
    fn complete_header_http_packet() {
        let mut parsed_packet = ParsedPacket::new();
        handle_http_packet(
            IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10)),
            4444,
            IpAddr::V4(Ipv4Addr::new(11, 11, 11, 11)),
            WellKnownPorts::HTTP_PORT,
            HttpPacketType::Request,
            false,
            &BASIC_REQUEST[0..8],
            &mut parsed_packet,
        );

        assert!(parsed_packet.get_application_layer_packet().is_none());

        let mut parsed_packet = ParsedPacket::new();
        handle_http_packet(
            IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10)),
            4444,
            IpAddr::V4(Ipv4Addr::new(11, 11, 11, 11)),
            WellKnownPorts::HTTP_PORT,
            HttpPacketType::Request,
            false,
            &BASIC_REQUEST[8..],
            &mut parsed_packet,
        );

        let mut headers = [httparse::EMPTY_HEADER; 1024];
        let mut http_request = httparse::Request::new(&mut headers);
        let _ = http_request.parse(BASIC_REQUEST).unwrap();

        match parsed_packet.get_application_layer_packet().unwrap() {
            SerializablePacket::HttpRequestPacket(new_http_request) => {
                assert_eq!(
                    new_http_request.method,
                    http_request.method.unwrap().to_owned()
                );
                assert_eq!(new_http_request.path, http_request.path.unwrap().to_owned());
                assert_eq!(new_http_request.version, http_request.version.unwrap());
                assert_eq!(
                    new_http_request.headers,
                    http_request
                        .headers
                        .iter()
                        .map(|header| {
                            (
                                header.name.to_string(),
                                std::str::from_utf8(header.value)
                                    .unwrap_or("Not valid UTF8")
                                    .to_owned(),
                            )
                        })
                        .collect::<Vec<(String, String)>>()
                );
                assert!(matches!(new_http_request.payload, HttpContentType::None));
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn valid_http_request_with_no_length_indication() {
        let mut parsed_packet = ParsedPacket::new();
        handle_http_packet(
            IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10)),
            4444,
            IpAddr::V4(Ipv4Addr::new(11, 11, 11, 11)),
            WellKnownPorts::HTTP_PORT,
            HttpPacketType::Request,
            false,
            BASIC_REQUEST,
            &mut parsed_packet,
        );

        let mut headers = [httparse::EMPTY_HEADER; 1024];
        let mut http_request = httparse::Request::new(&mut headers);
        let _ = http_request.parse(BASIC_REQUEST).unwrap();

        match parsed_packet.get_application_layer_packet().unwrap() {
            SerializablePacket::HttpRequestPacket(new_http_request) => {
                assert_eq!(
                    new_http_request.method,
                    http_request.method.unwrap().to_owned()
                );
                assert_eq!(new_http_request.path, http_request.path.unwrap().to_owned());
                assert_eq!(new_http_request.version, http_request.version.unwrap());
                assert_eq!(
                    new_http_request.headers,
                    http_request
                        .headers
                        .iter()
                        .map(|header| {
                            (
                                header.name.to_string(),
                                std::str::from_utf8(header.value)
                                    .unwrap_or("Not valid UTF8")
                                    .to_owned(),
                            )
                        })
                        .collect::<Vec<(String, String)>>()
                );
                assert!(matches!(new_http_request.payload, HttpContentType::None));
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn valid_http_response_with_no_length_indication_and_no_fin_set() {
        let mut parsed_packet = ParsedPacket::new();
        handle_http_packet(
            IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10)),
            WellKnownPorts::HTTP_PORT,
            IpAddr::V4(Ipv4Addr::new(11, 11, 11, 11)),
            4444,
            HttpPacketType::Response,
            false,
            BASIC_RESPONSE,
            &mut parsed_packet,
        );

        assert!(parsed_packet.get_application_layer_packet().is_none());
    }

    #[test]
    fn valid_http_response_with_no_length_indication_and_fin_set() {
        let mut parsed_packet = ParsedPacket::new();
        handle_http_packet(
            IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10)),
            WellKnownPorts::HTTP_PORT,
            IpAddr::V4(Ipv4Addr::new(11, 11, 11, 11)),
            4444,
            HttpPacketType::Response,
            true,
            BASIC_RESPONSE,
            &mut parsed_packet,
        );

        let mut headers = [httparse::EMPTY_HEADER; 1024];
        let mut http_response = httparse::Response::new(&mut headers);
        let _ = http_response.parse(BASIC_RESPONSE).unwrap();

        match parsed_packet.get_application_layer_packet().unwrap() {
            SerializablePacket::HttpResponsePacket(new_http_response) => {
                assert_eq!(new_http_response.version, http_response.version.unwrap());
                assert_eq!(new_http_response.code, http_response.code.unwrap());
                assert_eq!(
                    new_http_response.reason,
                    http_response.reason.unwrap().to_owned()
                );
                assert_eq!(
                    new_http_response.headers,
                    http_response
                        .headers
                        .iter()
                        .map(|header| {
                            (
                                header.name.to_string(),
                                std::str::from_utf8(header.value)
                                    .unwrap_or("Not valid UTF8")
                                    .to_owned(),
                            )
                        })
                        .collect::<Vec<(String, String)>>()
                );
                assert!(matches!(new_http_response.payload, HttpContentType::None));
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn valid_http_response_with_length_indication() {
        let mut headers = [httparse::EMPTY_HEADER; 1024];
        let mut http_response = httparse::Response::new(&mut headers);
        let _ = http_response.parse(CONTENT_LENGTH_ENDED_RESPONSE).unwrap();

        let result = packet_is_ended(
            CONTENT_LENGTH_ENDED_RESPONSE,
            1,
            &mut headers,
            HttpPacketType::Response,
            false,
        );

        assert_eq!(result, false);

        let result = packet_is_ended(
            CONTENT_LENGTH_ENDED_RESPONSE,
            CONTENT_LENGTH_ENDED_LENGTH,
            &mut headers,
            HttpPacketType::Response,
            false,
        );

        assert_eq!(result, true);
    }

    #[test]
    fn valid_http_response_with_transfer_encoding_chunked() {
        let mut headers = [httparse::EMPTY_HEADER; 1024];
        let mut http_response = httparse::Response::new(&mut headers);
        let _ = http_response.parse(CHUNKED_RESPONSE).unwrap();

        let result = packet_is_ended(
            &CHUNKED_RESPONSE[0..50],
            CHUNKED_RESPONSE_LENGTH,
            &mut headers,
            HttpPacketType::Response,
            false,
        );

        assert_eq!(result, false);

        let result = packet_is_ended(
            CHUNKED_RESPONSE,
            CHUNKED_RESPONSE_LENGTH,
            &mut headers,
            HttpPacketType::Response,
            false,
        );

        assert_eq!(result, true);
    }

    // Get Header
    #[test]
    fn get_existent_included_header() {
        let mut headers = [httparse::EMPTY_HEADER; 1024];
        let mut http_response = httparse::Response::new(&mut headers);
        let _ = http_response.parse(CONTENT_LENGTH_ENDED_RESPONSE).unwrap();

        match get_header_value(HeaderNamesValues::CONTENT_LENGTH, &headers) {
            Some(value) => assert_eq!(value.parse::<usize>().unwrap(), CONTENT_LENGTH_ENDED_LENGTH),
            _ => unreachable!(),
        }
    }

    #[test]
    fn get_existent_not_included_header() {
        let mut headers = [httparse::EMPTY_HEADER; 1024];
        let mut http_response = httparse::Response::new(&mut headers);
        let _ = http_response.parse(BASIC_RESPONSE).unwrap();

        match get_header_value(HeaderNamesValues::CONTENT_LENGTH, &headers) {
            None => assert!(true),
            _ => unreachable!(),
        }
    }

    #[test]
    fn get_inexistent_not_included_header() {
        let mut headers = [httparse::EMPTY_HEADER; 1024];
        let mut http_response = httparse::Response::new(&mut headers);
        let _ = http_response.parse(BASIC_RESPONSE).unwrap();

        match get_header_value("miao", &headers) {
            None => assert!(true),
            _ => unreachable!(),
        }
    }

    // Charset
    #[test]
    fn default_charset() {
        let text = "miao";
        let mime = "text/html".parse::<Mime>().unwrap();
        let result = get_http_type(mime, text.as_bytes().to_vec(), None);

        match result {
            HttpContentType::TextDefaultDecoded(decoded) => assert_eq!(text, decoded),
            _ => unreachable!(),
        }
    }

    #[test]
    fn provided_valid_charset() {
        let text = "miao";
        let mime = "text/html; charset=utf-8".parse::<Mime>().unwrap();
        let result = get_http_type(mime, text.as_bytes().to_vec(), None);

        match result {
            HttpContentType::TextCorrectlyDecoded(decoded) => assert_eq!(text, decoded),
            _ => unreachable!(),
        }
    }

    #[test]
    fn provided_invalid_charset() {
        let text = "業\r\nmiao\t潡";
        let mime = "text/html; charset=utf-16".parse::<Mime>().unwrap();
        let result = get_http_type(mime, text.as_bytes().to_vec(), None);

        match result {
            HttpContentType::TextMalformedDecoded(_) => assert!(true),
            _ => unreachable!(),
        }
    }

    #[test]
    fn transfer_encoding_chunked_last_chunk_formatted_wrongly() {
        println!(
            "{:?}",
            &CHUNKED_LAST_CHUNK_NOT_ENDED_RESPONSE[CHUNKED_LAST_CHUNK_NOT_ENDED_RESPONSE.len()
                - CHUNKED_LAST_CHUNK_NOT_ENDED_RESPONSE_LENGTH..]
        );
        let result = merge_chunks(
            CHUNKED_LAST_CHUNK_NOT_ENDED_RESPONSE[CHUNKED_LAST_CHUNK_NOT_ENDED_RESPONSE.len()
                - CHUNKED_LAST_CHUNK_NOT_ENDED_RESPONSE_LENGTH..]
                .as_bytes()
                .to_vec(),
        );

        match result {
            Err(HttpParsingError::TransferEncodingMalformed(str)) => {
                assert_eq!(
                    str,
                    "Malformed Transfer-Encoding HTTP Packet: last chunk is too small"
                );
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn transfer_encoding_chunked_length_not_valid_hexadecimal() {
        let result = merge_chunks(
            CHUNKED_NOT_HEXA_RESPONSE
                [CHUNKED_NOT_HEXA_RESPONSE.len() - CHUNKED_NOT_HEXA_RESPONSE_LENGTH..]
                .as_bytes()
                .to_vec(),
        );

        match result {
            Err(HttpParsingError::TransferEncodingMalformed(str)) => {
                assert_eq!(str, "Malformed Transfer-Encoding HTTP Packet: chunk's length not valid Hexadecimal character (\\x82)");
            }
            _ => unreachable!(),
        }
    }

    // Encoding

    #[test]
    fn valid_gzip_encoded_response() {
        let result = decode_payload(
            &mut GZIP_ENCODED_RESPONSE
                [GZIP_ENCODED_RESPONSE.len() - GZIP_ENCODED_RESPONSE_LENGTH..]
                .to_vec(),
            "gzip",
        );

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), DECODED_PAYLOAD);
    }

    #[test]
    fn valid_zlib_encoded_response() {
        let result = decode_payload(
            &mut ZLIB_ENCODED_RESPONSE
                [ZLIB_ENCODED_RESPONSE.len() - ZLIB_ENCODED_RESPONSE_LENGTH..]
                .to_vec(),
            "zlib",
        );

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), DECODED_PAYLOAD);
    }

    #[test]
    fn valid_deflate_encoded_response() {
        let result = decode_payload(
            &mut DEFLATE_ENCODED_RESPONSE
                [DEFLATE_ENCODED_RESPONSE.len() - DEFLATE_ENCODED_RESPONSE_LENGTH..]
                .to_vec(),
            "deflate",
        );

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), DECODED_PAYLOAD);
    }

    #[test]
    fn invalid_gzip_encoded_response() {
        let result = decode_payload(&mut b"ciao".to_vec(), "gzip");

        match result {
            Err(HttpParsingError::DecodingPayloadFailed(ext, str_ext)) => {
                assert_eq!(ext, "gzip");
                assert_eq!(str_ext, "Decoding failed for: gzip");
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn unknown_encoding_algorithm() {
        let result = decode_payload(&mut b"ciao".to_vec(), "tz");

        match result {
            Err(HttpParsingError::UnknownDecodingAlgorithm(ext, str_ext)) => {
                assert_eq!(ext, "tz");
                assert_eq!(str_ext, "Unknown algorithm: tz");
            }
            _ => unreachable!(),
        }
    }
}
