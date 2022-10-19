//! TLS Packet parsing

use std::net::IpAddr;

use log::debug;
use log::error;
use log::warn;
use tls_parser::nom::error::ErrorKind;
use tls_parser::parse_tls_plaintext;
use tls_parser::parse_tls_record_header;
use tls_parser::{parse_tls_encrypted, TlsMessage, TlsMessageHandshake};

use crate::serializable_packet::application::*;
use crate::serializable_packet::ParsedPacket;
use crate::serializable_packet::SerializablePacket;
use crate::ACTIVE_TLS_PARSERS;

/// Build a TLS packet from a transport-layer packet, save it in a Parsed Packet
pub fn handle_tls_packet(
    source_ip: IpAddr,
    source_port: u16,
    dest_ip: IpAddr,
    dest_port: u16,
    packet: &[u8],
    parsed_packet: &mut ParsedPacket,
) {
    ACTIVE_TLS_PARSERS.with(|parsers| {
        let mut parsers = parsers.borrow_mut();
        let current_payload = parsers
            .entry(((source_ip, source_port), (dest_ip, dest_port)))
            .and_modify(|payload| payload.append(packet.to_vec().as_mut()))
            .or_insert(packet.to_vec());

        let mut tls_packet = SerializableTlsPacket::default();
        let mut custom_messages = vec![];

        while !current_payload.is_empty() {
            let result = parse_tls_plaintext(current_payload);
            match result {
                Ok((rem, record)) => {
                    for (i, msg) in record.msg.iter().enumerate() {
                        debug!(
                            "[{i}]: TLS Record Packet: {}:{} > {}:{}; Version: {}, Record Type: {:?}, Len: {}, Payload: {:?}",
                            source_ip, source_port, dest_ip, dest_port, record.hdr.version, record.hdr.record_type, record.hdr.len, msg
                        );
                    }

                    parse_messages(record.msg, &mut custom_messages);

                    if rem.is_empty() {
                        tls_packet.set_version(record.hdr.version);
                        tls_packet.set_length(record.hdr.len);

                        current_payload.clear();
                        parsers.remove(&((source_ip, source_port), (dest_ip, dest_port)));
                        break;
                    } else {
                        let end = current_payload.len() - rem.len();
                        current_payload.drain(..end);
                        continue;
                    }
                },
                Err(tls_parser::nom::Err::Incomplete(_)) => break,
                Err(tls_parser::nom::Err::Error(e)) => {
                    match e.code {
                        ErrorKind::Switch => {
                            warn!(
                                "TLS Ignored unknown record: {}:{} > {}:{}; Length: {}",
                                source_ip, source_port, dest_ip, dest_port, current_payload.len()
                            );
                            custom_messages.push(CustomTlsMessage::Malformed(
                                CustomMalformedMessage::new(
                                    None,
                                    None,
                                    TlsMalformedError::UnknownRecord(
                                        "Unknown record type".to_owned()
                                    ),
                                    current_payload
                                )
                            ));

                            current_payload.clear();
                            parsers.remove(&((source_ip, source_port), (dest_ip, dest_port)));
                            break;
                        },
                        ErrorKind::TooLarge => {
                            let result = parse_tls_record_header(current_payload);
                            match result {
                                Ok((_, record)) => {
                                    warn!(
                                        "TLS Length Error: {}:{} > {}:{}; Length: {}",
                                        source_ip, source_port, dest_ip, dest_port, current_payload.len()
                                    );

                                    custom_messages.push(CustomTlsMessage::Malformed(
                                        CustomMalformedMessage::new(
                                            Some(record.version),
                                            Some(record.record_type),
                                            TlsMalformedError::LengthTooLarge(
                                                "Max Record size exceeded (RFC8446 5.1)".to_owned()
                                            ),
                                            current_payload
                                        )
                                    ));
                                },
                                _ => ()
                            }

                            current_payload.clear();
                            parsers.remove(&((source_ip, source_port), (dest_ip, dest_port)));
                            break;
                        },
                        _ => ()
                    }
                }
                Err(tls_parser::nom::Err::Failure(_)) => {
                    error!("[FAILURE] Malformed TLS");
                    current_payload.clear();
                    parsers.remove(&((source_ip, source_port), (dest_ip, dest_port)));
                    break;
                }
            };

            let result = parse_tls_encrypted(current_payload);
            match result {
                Ok((rem, record)) => {
                    debug!(
                        "TLS Encrypted Packet: {}:{} > {}:{}; Version: {}, Record Type: {:?}, Len: {}",
                        source_ip, source_port, dest_ip, dest_port, record.hdr.version, record.hdr.record_type, record.hdr.len
                    );

                    custom_messages.push(CustomTlsMessage::Encrypted(
                        CustomEncryptedMessage::new(record.msg.blob, record.hdr.version, record.hdr.record_type)
                    ));

                    if rem.is_empty() {
                        tls_packet.set_version(record.hdr.version);
                        tls_packet.set_length(record.hdr.len);

                        current_payload.clear();
                        parsers.remove(&((source_ip, source_port), (dest_ip, dest_port)));
                        break;
                    } else {
                        let end = current_payload.len() - rem.len();
                        current_payload.drain(..end);
                        continue;
                    }
                }
                Err(tls_parser::nom::Err::Incomplete(_)) => break,
                Err(tls_parser::nom::Err::Error(e)) => {
                    match e.code {
                        ErrorKind::Switch => {
                            warn!(
                                "TLS Ignored unknown record: {}:{} > {}:{}; Length: {}",
                                source_ip, source_port, dest_ip, dest_port, current_payload.len()
                            );

                            custom_messages.push(CustomTlsMessage::Malformed(
                                CustomMalformedMessage::new(
                                    None,
                                    None,
                                    TlsMalformedError::UnknownRecord(
                                        "Unknown record type".to_owned()
                                    ),
                                    current_payload
                                )
                            ));
                        },
                        ErrorKind::TooLarge => {
                            let result = parse_tls_record_header(current_payload);
                            match result {
                                Ok((_, record)) => {
                                    warn!(
                                        "TLS Length Error: {}:{} > {}:{}; Length: {}",
                                        source_ip, source_port, dest_ip, dest_port, current_payload.len()
                                    );

                                    custom_messages.push(CustomTlsMessage::Malformed(
                                        CustomMalformedMessage::new(
                                            Some(record.version),
                                            Some(record.record_type),
                                            TlsMalformedError::LengthTooLarge(
                                                "Max Record size exceeded (RFC8446 5.1)".to_owned()
                                            ),
                                            current_payload
                                        )
                                    ));
                                },
                                _ => ()
                            }
                        },
                        e => {
                            warn!("ENC [{:?}] {}:{} > {}:{}; Malformed TLS", e, source_ip, source_port, dest_ip, dest_port);
                        }
                    }

                    current_payload.clear();
                    parsers.remove(&((source_ip, source_port), (dest_ip, dest_port)));
                    break;
                },
                Err(_) => {
                    current_payload.clear();
                    parsers.remove(&((source_ip, source_port), (dest_ip, dest_port)));
                    break;
                },
            }
        }

        if !custom_messages.is_empty() {
            parsed_packet.set_application_layer_packet(Some(
                SerializablePacket::TlsPacket(
                    SerializableTlsPacket {
                        version: tls_packet.version,
                        messages: custom_messages,
                        length: tls_packet.length,
                    }
                ),
            ));
        }
    });
}

fn parse_messages(messages: Vec<TlsMessage>, custom_messages: &mut Vec<CustomTlsMessage>) {
    for msg in &messages {
        match msg {
            TlsMessage::Handshake(msg) => match msg {
                TlsMessageHandshake::ClientHello(msg) => {
                    custom_messages.push(CustomTlsMessage::Handshake(
                        CustomHandshakeMessage::ClientHello(ClientHelloMessage::new(msg)),
                    ));
                }
                TlsMessageHandshake::ServerHello(msg) => {
                    custom_messages.push(CustomTlsMessage::Handshake(
                        CustomHandshakeMessage::ServerHello(ServerHelloMessage::new(msg)),
                    ));
                }
                TlsMessageHandshake::Certificate(msg) => {
                    custom_messages.push(CustomTlsMessage::Handshake(
                        CustomHandshakeMessage::Certificate(CertificateMessage::new(msg)),
                    ));
                }
                TlsMessageHandshake::CertificateRequest(msg) => {
                    custom_messages.push(CustomTlsMessage::Handshake(
                        CustomHandshakeMessage::CertificateRequest(CertificateRequestMessage::new(
                            msg,
                        )),
                    ));
                }
                TlsMessageHandshake::CertificateStatus(msg) => {
                    custom_messages.push(CustomTlsMessage::Handshake(
                        CustomHandshakeMessage::CertificateStatus(CertificateStatusMessage::new(
                            msg,
                        )),
                    ));
                }
                TlsMessageHandshake::CertificateVerify(msg) => {
                    custom_messages.push(CustomTlsMessage::Handshake(
                        CustomHandshakeMessage::CertificateVerify(CertificateVerifyMessage::new(
                            msg,
                        )),
                    ));
                }
                TlsMessageHandshake::ClientKeyExchange(msg) => {
                    custom_messages.push(CustomTlsMessage::Handshake(
                        CustomHandshakeMessage::ClientKeyExchange(ClientKeyExchangeMessage::new(
                            msg,
                        )),
                    ));
                }
                TlsMessageHandshake::EndOfEarlyData => {
                    custom_messages.push(CustomTlsMessage::Handshake(
                        CustomHandshakeMessage::EndOfEarlyData,
                    ));
                }
                TlsMessageHandshake::Finished(msg) => {
                    custom_messages.push(CustomTlsMessage::Handshake(
                        CustomHandshakeMessage::Finished(FinishedMessage::new(msg)),
                    ));
                }
                TlsMessageHandshake::HelloRequest => {
                    custom_messages.push(CustomTlsMessage::Handshake(
                        CustomHandshakeMessage::HelloRequest,
                    ));
                }
                TlsMessageHandshake::HelloRetryRequest(msg) => {
                    custom_messages.push(CustomTlsMessage::Handshake(
                        CustomHandshakeMessage::HelloRetryRequest(HelloRetryRequestMessage::new(
                            msg,
                        )),
                    ));
                }
                TlsMessageHandshake::KeyUpdate(msg) => {
                    custom_messages.push(CustomTlsMessage::Handshake(
                        CustomHandshakeMessage::KeyUpdate(match msg {
                            0x0 => "0x0: Requested".to_owned(),
                            0x1 => "0x1: Not Requested".to_owned(),
                            x => format!("{}: Unknown", x),
                        }),
                    ));
                }
                TlsMessageHandshake::NewSessionTicket(msg) => {
                    custom_messages.push(CustomTlsMessage::Handshake(
                        CustomHandshakeMessage::NewSessionTicket(NewSessionTicketMessage::new(msg)),
                    ));
                }
                TlsMessageHandshake::NextProtocol(msg) => {
                    custom_messages.push(CustomTlsMessage::Handshake(
                        CustomHandshakeMessage::NextProtocol(NextProtocolMessage::new(msg)),
                    ));
                }
                TlsMessageHandshake::ServerDone(msg) => {
                    custom_messages.push(CustomTlsMessage::Handshake(
                        CustomHandshakeMessage::ServerDone(ServerDoneMessage::new(msg)),
                    ));
                }
                TlsMessageHandshake::ServerHelloV13Draft18(msg) => {
                    custom_messages.push(CustomTlsMessage::Handshake(
                        CustomHandshakeMessage::ServerHelloV13Draft18(
                            ServerHelloV13Draft18Message::new(msg),
                        ),
                    ));
                }
                TlsMessageHandshake::ServerKeyExchange(msg) => {
                    custom_messages.push(CustomTlsMessage::Handshake(
                        CustomHandshakeMessage::ServerKeyExchange(ServerKeyExchangeMessage::new(
                            msg,
                        )),
                    ));
                }
            },
            TlsMessage::Alert(msg) => {
                custom_messages.push(CustomTlsMessage::Alert(CustomAlertMessage::new(msg)));
            }
            TlsMessage::Heartbeat(msg) => {
                custom_messages.push(CustomTlsMessage::Heartbeat(CustomHeartbeatMessage::new(
                    msg,
                )));
            }
            TlsMessage::ChangeCipherSpec => {
                custom_messages.push(CustomTlsMessage::ChangeCipherSpec);
            }
            TlsMessage::ApplicationData(msg) => {
                custom_messages.push(CustomTlsMessage::ApplicationData(
                    CustomApplicationDataMessage::new(msg.blob),
                ));
            }
        }
    }
}

// - A test for each MessageType

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use tls_parser::{
        parse_ecdh_params, parse_tls_extensions, parse_tls_plaintext, ECParametersContent,
        TlsClientKeyExchangeContents, TlsMessage, TlsMessageHandshake,
    };

    use crate::serializable_packet::{
        application::{
            parse_custom_tls_extensions, ClientParameters, CustomEcContent, CustomHandshakeMessage,
            CustomTlsMessage, ServerParameters, TlsMalformedError,
        },
        ParsedPacket, SerializablePacket,
    };

    use super::handle_tls_packet;

    const SERVER_HELLO: &[u8] = &[
        0x16, 0x03, 0x03, 0x00, 0x52, 0x02, 0x00, 0x00, 0x4e, 0x03, 0x03, 0x6a, 0x24, 0x0b, 0x23,
        0x9a, 0x87, 0xb2, 0xc3, 0x41, 0xa5, 0x1b, 0x07, 0x9d, 0xc7, 0x7f, 0x98, 0x59, 0x0c, 0xe6,
        0x4e, 0xbe, 0x6b, 0x28, 0xd2, 0xbf, 0x95, 0xb5, 0x5c, 0x89, 0xf6, 0x0e, 0xba, 0x00, 0xc0,
        0x2f, 0x00, 0x00, 0x26, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b,
        0x00, 0x04, 0x03, 0x00, 0x01, 0x02, 0x00, 0x23, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
        0x17, 0x00, 0x00, 0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 0x68, 0x32,
    ];

    const SERVER_HELLO_DONE: &[u8] = &[0x16, 0x03, 0x03, 0x00, 0x04, 0x0e, 0x00, 0x00, 0x00];

    const SERVER_KEY_EXCHANGE: &[u8] = &[
        0x16, 0x03, 0x03, 0x01, 0x2c, 0x0c, 0x00, 0x01, 0x28, 0x03, 0x00, 0x1d, 0x20, 0x22, 0x9a,
        0xc2, 0x6d, 0x4f, 0xb0, 0x7d, 0xcd, 0xa2, 0x12, 0x2f, 0x8a, 0x8d, 0x17, 0x62, 0x8e, 0x69,
        0x33, 0xac, 0x59, 0xe6, 0xda, 0x6e, 0x5e, 0x8f, 0xd7, 0xc9, 0xdc, 0xf6, 0x3b, 0x5d, 0x2d,
        0x06, 0x01, 0x01, 0x00, 0x1d, 0x68, 0x23, 0x67, 0xb6, 0x77, 0x7e, 0x1a, 0xa3, 0xe1, 0x0d,
        0x7f, 0xd8, 0xc1, 0xab, 0xf7, 0xbb, 0xb6, 0x1e, 0x87, 0x7c, 0x98, 0xab, 0x76, 0xe0, 0x50,
        0x70, 0xbd, 0xb4, 0x2d, 0xc9, 0xe2, 0xd8, 0xb8, 0x53, 0x0e, 0xdd, 0xc6, 0x39, 0x2d, 0x07,
        0x8f, 0x7b, 0x0e, 0x01, 0x32, 0xee, 0x80, 0x45, 0x12, 0xc8, 0x05, 0x52, 0xa1, 0x6f, 0x03,
        0xfc, 0xda, 0xab, 0xb4, 0xcd, 0xf8, 0x89, 0x00, 0x04, 0xfa, 0x61, 0xab, 0xcb, 0x57, 0x1e,
        0x36, 0xa6, 0x51, 0xb8, 0xd1, 0xae, 0x9a, 0xdf, 0xe4, 0x73, 0x1f, 0x95, 0x2a, 0x57, 0x08,
        0x10, 0xa5, 0x5d, 0x67, 0x05, 0x6e, 0x82, 0xca, 0xcd, 0x1e, 0xbe, 0xf2, 0x30, 0xb2, 0x76,
        0xdc, 0x1e, 0x8a, 0x26, 0x72, 0x2e, 0xc2, 0xc8, 0xdc, 0xf2, 0x0b, 0xb1, 0x1b, 0xa5, 0x76,
        0x93, 0x08, 0x8b, 0x87, 0x26, 0xb1, 0xa9, 0xf5, 0x52, 0x09, 0xae, 0x42, 0xdb, 0x4e, 0x42,
        0x3c, 0x71, 0x56, 0xab, 0x94, 0xf0, 0xb0, 0x85, 0xd2, 0xe6, 0xb5, 0x76, 0x17, 0xd1, 0x09,
        0xa9, 0x34, 0xc0, 0x6a, 0x96, 0x1b, 0x2d, 0x69, 0x00, 0x2d, 0xa0, 0x4d, 0xf4, 0x24, 0xb4,
        0x3f, 0x9e, 0x27, 0x40, 0xdb, 0xa8, 0xb5, 0xd9, 0xff, 0x85, 0xb3, 0xad, 0xcf, 0xd0, 0x24,
        0x4d, 0x71, 0x7b, 0xe9, 0x2b, 0xd4, 0xa6, 0x31, 0x8f, 0x6d, 0xe4, 0x90, 0x07, 0x89, 0xc6,
        0xa3, 0xad, 0xc3, 0xc6, 0x92, 0xb3, 0x0f, 0xc5, 0x1d, 0x7f, 0x63, 0x2a, 0x23, 0x23, 0xe9,
        0x1a, 0xe6, 0xd5, 0x25, 0x7e, 0xbd, 0x74, 0xf6, 0x1c, 0x8b, 0x33, 0x95, 0x94, 0x4c, 0x64,
        0x38, 0xa6, 0x48, 0x89, 0xf1, 0x33, 0xd5, 0x99, 0x0b, 0x66, 0x9b, 0xab, 0xe3, 0xb5, 0x73,
        0x88, 0xea, 0xc6, 0xb3, 0x66, 0xa5, 0xc8, 0xfd, 0x7c, 0xa5, 0x83, 0x4c, 0xb1, 0xb5, 0x6e,
        0xa8, 0x7c, 0xa8, 0x18, 0x55,
    ];

    const CHANGE_CIPHER_SPEC: &[u8] = &[0x14, 0x03, 0x03, 0x00, 0x01, 0x01];

    const CLIENT_HELLO: &[u8] = &[
        0x16, 0x03, 0x01, 0x02, 0x8e, 0x01, 0x00, 0x02, 0x8a, 0x03, 0x03, 0x26, 0x09, 0x3b, 0x16,
        0x74, 0x1b, 0x00, 0x5f, 0xae, 0xe1, 0x6d, 0x66, 0x7d, 0xf8, 0x0d, 0xa3, 0xd1, 0x30, 0x44,
        0xf8, 0x03, 0xed, 0x56, 0xaf, 0x5d, 0x9b, 0xbc, 0x41, 0x5a, 0x00, 0xd7, 0x23, 0x20, 0x80,
        0x89, 0xc4, 0xda, 0x4e, 0x69, 0x69, 0xc8, 0x76, 0x57, 0xc4, 0x2a, 0xa7, 0x9f, 0xac, 0x4f,
        0x20, 0x50, 0x94, 0x8c, 0x8f, 0x7c, 0xd2, 0x81, 0xde, 0x79, 0x35, 0x76, 0xd0, 0xd0, 0xa7,
        0xca, 0x00, 0x22, 0x13, 0x01, 0x13, 0x03, 0x13, 0x02, 0xc0, 0x2b, 0xc0, 0x2f, 0xcc, 0xa9,
        0xcc, 0xa8, 0xc0, 0x2c, 0xc0, 0x30, 0xc0, 0x0a, 0xc0, 0x09, 0xc0, 0x13, 0xc0, 0x14, 0x00,
        0x9c, 0x00, 0x9d, 0x00, 0x2f, 0x00, 0x35, 0x01, 0x00, 0x02, 0x1f, 0x00, 0x00, 0x00, 0x13,
        0x00, 0x11, 0x00, 0x00, 0x0e, 0x77, 0x77, 0x77, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
        0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x17, 0x00, 0x00, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0a,
        0x00, 0x0e, 0x00, 0x0c, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x01, 0x00, 0x01,
        0x01, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x10, 0x00, 0x0e, 0x00, 0x0c, 0x02, 0x68,
        0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31, 0x00, 0x05, 0x00, 0x05, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x00, 0x0a, 0x00, 0x08, 0x04, 0x03, 0x05, 0x03, 0x06,
        0x03, 0x02, 0x03, 0x00, 0x33, 0x00, 0x6b, 0x00, 0x69, 0x00, 0x1d, 0x00, 0x20, 0xc4, 0x8e,
        0x49, 0x76, 0x12, 0x0f, 0x50, 0x4c, 0x8a, 0xed, 0x0d, 0x88, 0x26, 0x0a, 0x50, 0xa9, 0xb4,
        0x54, 0x79, 0x13, 0x32, 0xb2, 0x73, 0x5e, 0xe9, 0x3c, 0x1b, 0x46, 0x9e, 0x0c, 0x48, 0x7f,
        0x00, 0x17, 0x00, 0x41, 0x04, 0x3b, 0x57, 0xc5, 0x56, 0xa4, 0x1b, 0x27, 0x35, 0x2d, 0xfb,
        0xe0, 0x15, 0x76, 0x44, 0x4f, 0x97, 0xa6, 0x3c, 0x15, 0xa1, 0x3b, 0x14, 0x1f, 0xfb, 0xa7,
        0x87, 0x41, 0xd5, 0x19, 0x2f, 0xf5, 0x15, 0x26, 0x07, 0xf6, 0xfc, 0x71, 0x1f, 0xab, 0x7d,
        0x67, 0x66, 0x48, 0x44, 0x30, 0x5e, 0xed, 0xb7, 0x6c, 0xdc, 0x17, 0x8b, 0xec, 0xd1, 0x64,
        0xba, 0x02, 0xb4, 0x1d, 0x8a, 0xa2, 0x3e, 0x2b, 0x0d, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x2b,
        0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03, 0x00, 0x0d, 0x00, 0x18, 0x00, 0x16, 0x04, 0x03,
        0x05, 0x03, 0x06, 0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06,
        0x01, 0x02, 0x03, 0x02, 0x01, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x1c, 0x00, 0x02,
        0x40, 0x01, 0x00, 0x29, 0x01, 0x16, 0x00, 0xf1, 0x00, 0xeb, 0x02, 0xe5, 0x1e, 0xf2, 0x8d,
        0xc2, 0x28, 0x05, 0x9a, 0xf6, 0x33, 0x4f, 0x7b, 0x5f, 0x7d, 0x5f, 0xd8, 0xb0, 0xa6, 0xbe,
        0x1c, 0xfe, 0x79, 0xea, 0xe7, 0xbe, 0xa4, 0xcb, 0x7e, 0xa8, 0x75, 0xf1, 0x95, 0xb7, 0x15,
        0x1c, 0x1d, 0x25, 0x66, 0x76, 0x19, 0xb4, 0x6b, 0xd7, 0xf9, 0x67, 0x63, 0x73, 0x49, 0x01,
        0x1f, 0x2f, 0xec, 0x80, 0x5d, 0x90, 0xc7, 0xd2, 0x51, 0x57, 0x04, 0x0a, 0x3d, 0x29, 0x01,
        0xc7, 0x80, 0x29, 0x7c, 0x34, 0xbe, 0x97, 0x28, 0x4d, 0xf1, 0x87, 0x4b, 0x38, 0x5b, 0x86,
        0xa5, 0x47, 0xd9, 0xf4, 0x6f, 0x35, 0xde, 0xc2, 0x50, 0x08, 0x41, 0x4e, 0xc7, 0xb5, 0x13,
        0x8a, 0xa0, 0xde, 0x38, 0x82, 0x80, 0x63, 0x5d, 0x82, 0x0e, 0x42, 0x6c, 0x69, 0x8d, 0x80,
        0x18, 0xa1, 0xcd, 0x90, 0x86, 0x7d, 0xd5, 0xf7, 0x1b, 0xbe, 0x22, 0x54, 0x76, 0x86, 0x89,
        0xec, 0x45, 0xdc, 0xc5, 0x82, 0x27, 0xef, 0xd6, 0xc9, 0x7b, 0xc2, 0x38, 0xeb, 0x2f, 0xd1,
        0xd8, 0xb8, 0xa2, 0x1f, 0x3f, 0xc6, 0x17, 0xc9, 0x40, 0x09, 0xfd, 0x96, 0xf7, 0xbe, 0x7a,
        0x56, 0xa1, 0xb4, 0xda, 0x64, 0xac, 0xde, 0xa3, 0x49, 0x66, 0xa5, 0x38, 0x93, 0x37, 0x5c,
        0x09, 0x73, 0x97, 0xb2, 0x65, 0xce, 0xf2, 0x46, 0x07, 0x3a, 0x4b, 0xd9, 0x69, 0xbb, 0x0a,
        0x8e, 0x44, 0xbd, 0x6c, 0x7b, 0x46, 0x8e, 0xc5, 0x70, 0x80, 0x90, 0x6d, 0xa3, 0x68, 0x3a,
        0x37, 0x60, 0x68, 0x81, 0x96, 0x3d, 0x3d, 0x93, 0xc7, 0xfa, 0x33, 0x65, 0xe8, 0x81, 0xe7,
        0xf9, 0x73, 0x10, 0xad, 0x38, 0xd4, 0xe8, 0x1f, 0x20, 0x4d, 0x49, 0x4c, 0x68, 0x46, 0x13,
        0x2f, 0xf0, 0x0c, 0x61, 0x2a, 0x7e, 0x1c, 0xe0, 0x35, 0x00, 0x21, 0x20, 0xba, 0x7a, 0x3e,
        0x20, 0x44, 0x3e, 0xb9, 0xd4, 0x1c, 0xb7, 0x96, 0x43, 0xab, 0xe6, 0x98, 0xbd, 0x53, 0x0f,
        0x24, 0x1d, 0x27, 0x61, 0x5b, 0x1a, 0x03, 0x19, 0x74, 0xe3, 0x56, 0xb5, 0xf4, 0x3f,
    ];

    const CLIENT_KEY_EXCHANGE: &[u8] = &[
        0x16, 0x03, 0x03, 0x00, 0x25, 0x10, 0x00, 0x00, 0x21, 0x20, 0x5d, 0xac, 0x5f, 0xf7, 0xd9,
        0xa5, 0x9b, 0x35, 0x32, 0xbf, 0xd1, 0xa8, 0xbf, 0x25, 0x94, 0x75, 0xea, 0x11, 0xb2, 0x36,
        0x67, 0xc0, 0x74, 0xe0, 0x5b, 0x68, 0x89, 0xbe, 0x6f, 0x6a, 0xf2, 0x10,
    ];

    const CERTIFICATE_STATUS: &[u8] = &[
        0x16, 0x03, 0x03, 0x01, 0xdf, 0x16, 0x00, 0x01, 0xdb, 0x01, 0x00, 0x01, 0xd7, 0x30, 0x82,
        0x01, 0xd3, 0x0a, 0x01, 0x00, 0xa0, 0x82, 0x01, 0xcc, 0x30, 0x82, 0x01, 0xc8, 0x06, 0x09,
        0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01, 0x04, 0x82, 0x01, 0xb9, 0x30, 0x82,
        0x01, 0xb5, 0x30, 0x81, 0x9e, 0xa2, 0x16, 0x04, 0x14, 0xb7, 0x6b, 0xa2, 0xea, 0xa8, 0xaa,
        0x84, 0x8c, 0x79, 0xea, 0xb4, 0xda, 0x0f, 0x98, 0xb2, 0xc5, 0x95, 0x76, 0xb9, 0xf4, 0x18,
        0x0f, 0x32, 0x30, 0x32, 0x32, 0x30, 0x39, 0x30, 0x38, 0x31, 0x39, 0x34, 0x33, 0x31, 0x35,
        0x5a, 0x30, 0x73, 0x30, 0x71, 0x30, 0x49, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02,
        0x1a, 0x05, 0x00, 0x04, 0x14, 0xe4, 0xe3, 0x95, 0xa2, 0x29, 0xd3, 0xd4, 0xc1, 0xc3, 0x1f,
        0xf0, 0x98, 0x0c, 0x0b, 0x4e, 0xc0, 0x09, 0x8a, 0xab, 0xd8, 0x04, 0x14, 0xb7, 0x6b, 0xa2,
        0xea, 0xa8, 0xaa, 0x84, 0x8c, 0x79, 0xea, 0xb4, 0xda, 0x0f, 0x98, 0xb2, 0xc5, 0x95, 0x76,
        0xb9, 0xf4, 0x02, 0x10, 0x09, 0x9c, 0x7f, 0x30, 0x07, 0xad, 0x2e, 0x23, 0x60, 0x2e, 0x58,
        0xd3, 0x49, 0x7d, 0xe0, 0x49, 0x80, 0x00, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x32, 0x30, 0x39,
        0x30, 0x38, 0x31, 0x39, 0x32, 0x37, 0x30, 0x31, 0x5a, 0xa0, 0x11, 0x18, 0x0f, 0x32, 0x30,
        0x32, 0x32, 0x30, 0x39, 0x31, 0x35, 0x31, 0x38, 0x34, 0x32, 0x30, 0x31, 0x5a, 0x30, 0x0d,
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82,
        0x01, 0x01, 0x00, 0x19, 0x93, 0xbf, 0x0f, 0x6f, 0x74, 0x47, 0x70, 0x09, 0x85, 0x30, 0x3e,
        0x79, 0xcd, 0x28, 0x0a, 0x77, 0x2f, 0xca, 0x80, 0xba, 0xf3, 0xf6, 0x63, 0xfb, 0x07, 0x7c,
        0x79, 0x60, 0xee, 0x94, 0x3f, 0x02, 0xb7, 0xad, 0xd3, 0x19, 0xe3, 0xa7, 0x9d, 0x04, 0x9a,
        0x0e, 0x0a, 0xd0, 0x1d, 0x36, 0xdb, 0xf4, 0xb4, 0x67, 0xa9, 0xe2, 0xd9, 0xe9, 0xc9, 0xf7,
        0x76, 0xdd, 0x70, 0xee, 0x7b, 0x78, 0x66, 0xa9, 0x77, 0xa5, 0x0d, 0xee, 0xf1, 0x49, 0x05,
        0xa8, 0xad, 0x89, 0x5b, 0x4f, 0xf1, 0x15, 0xb4, 0x52, 0x79, 0x11, 0xd1, 0xb9, 0xca, 0x37,
        0x21, 0xfc, 0x42, 0x1d, 0xa0, 0xf3, 0xcd, 0xab, 0xab, 0xca, 0x4f, 0x5d, 0xda, 0x66, 0x24,
        0x92, 0xd3, 0x4b, 0x6c, 0x93, 0x4d, 0x1e, 0x3f, 0x83, 0x2f, 0x39, 0xda, 0xb5, 0x3c, 0x8e,
        0x18, 0xa8, 0x72, 0x01, 0xee, 0x4d, 0x47, 0x37, 0x9b, 0x26, 0xc2, 0x7a, 0x85, 0xa8, 0x47,
        0xe8, 0x2c, 0x55, 0xe1, 0x8d, 0xba, 0xef, 0x64, 0x5f, 0xd0, 0x74, 0x91, 0x7c, 0x5b, 0x8a,
        0x26, 0x8f, 0xf3, 0xad, 0xf4, 0x11, 0x98, 0x0c, 0xf6, 0xfd, 0x50, 0x47, 0xb0, 0xec, 0x1c,
        0x1b, 0x59, 0x8f, 0x4c, 0x6d, 0x5a, 0x02, 0xa5, 0x8f, 0x4d, 0x1b, 0x19, 0xc9, 0x49, 0x87,
        0xcb, 0x13, 0xd5, 0x5c, 0x41, 0xb0, 0x8f, 0x1d, 0x5c, 0x01, 0xf1, 0xaf, 0x7c, 0x96, 0x51,
        0x7f, 0x97, 0x33, 0xa1, 0x80, 0x79, 0x3c, 0x2d, 0xb3, 0x1c, 0x0e, 0xc1, 0x76, 0xb5, 0x2b,
        0x1e, 0xc3, 0x58, 0x51, 0x8a, 0x0d, 0x86, 0x75, 0x5f, 0xb3, 0x4d, 0x3c, 0xc0, 0x53, 0x62,
        0xa8, 0x64, 0x4d, 0x53, 0x8c, 0xa6, 0x49, 0x79, 0x91, 0x14, 0xac, 0xb7, 0xeb, 0x70, 0xe4,
        0x47, 0xe6, 0x5a, 0xf8, 0xb3, 0x49, 0xe2, 0x66, 0xea, 0x4a, 0x88, 0x70, 0xd2, 0xb2, 0x63,
        0x29, 0x05, 0x28, 0x52,
    ];

    const ALERT: &[u8] = &[0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x46];

    const UNKNOWN_RECORD: &[u8] = &[0x63, 0x0e, 0x00, 0x00, 0x03, 0x0f, 0xf8, 0xec];

    const TOO_LARGE_RECORD: &[u8] = &[0x17, 0x03, 0x03, 0x40, 0x11, 0x0f, 0xf8, 0xec];

    #[test]
    fn valid_server_hello_tls_packet() {
        let mut parsed_packet = ParsedPacket::new(0);
        handle_tls_packet(
            IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10)),
            4444,
            IpAddr::V4(Ipv4Addr::new(11, 11, 11, 11)),
            443,
            SERVER_HELLO,
            &mut parsed_packet,
        );

        let (_, tls_packet) = parse_tls_plaintext(SERVER_HELLO).unwrap();
        match parsed_packet.get_application_layer_packet().unwrap() {
            SerializablePacket::TlsPacket(new_tls_packet) => {
                assert_eq!(
                    new_tls_packet.version,
                    format!("{}", tls_packet.hdr.version)
                );
                assert_eq!(new_tls_packet.length, tls_packet.hdr.len);
                assert_eq!(new_tls_packet.messages.len(), tls_packet.msg.len());

                match &new_tls_packet.messages[0] {
                    CustomTlsMessage::Handshake(CustomHandshakeMessage::ServerHello(
                        new_message,
                    )) => match &tls_packet.msg[0] {
                        TlsMessage::Handshake(TlsMessageHandshake::ServerHello(message)) => {
                            assert_eq!(new_message.version, format!("{:?}", message.version));
                            assert_eq!(new_message.rand_time, message.rand_time);
                            assert_eq!(new_message.rand_data, message.rand_data.to_vec());
                            assert_eq!(
                                new_message.session_id,
                                message.session_id.map_or(None, |v| Some(v.to_vec()))
                            );
                            assert_eq!(new_message.cipher, format!("{:?}", message.cipher));
                            assert_eq!(
                                new_message.compression,
                                format!("{:?}", message.compression)
                            );

                            match parse_tls_extensions(message.ext.unwrap_or(b"")) {
                                Ok((_, exts)) => assert_eq!(
                                    new_message.extensions,
                                    parse_custom_tls_extensions(exts)
                                ),
                                _ => unreachable!(),
                            }
                        }
                        _ => unreachable!(),
                    },
                    _ => unreachable!(),
                }
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn valid_server_done_tls_packet() {
        let mut parsed_packet = ParsedPacket::new(0);
        handle_tls_packet(
            IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10)),
            4444,
            IpAddr::V4(Ipv4Addr::new(11, 11, 11, 11)),
            443,
            SERVER_HELLO_DONE,
            &mut parsed_packet,
        );

        let (_, tls_packet) = parse_tls_plaintext(SERVER_HELLO_DONE).unwrap();
        match parsed_packet.get_application_layer_packet().unwrap() {
            SerializablePacket::TlsPacket(new_tls_packet) => {
                assert_eq!(
                    new_tls_packet.version,
                    format!("{}", tls_packet.hdr.version)
                );
                assert_eq!(new_tls_packet.length, tls_packet.hdr.len);
                assert_eq!(new_tls_packet.messages.len(), tls_packet.msg.len());

                match &new_tls_packet.messages[0] {
                    CustomTlsMessage::Handshake(CustomHandshakeMessage::ServerDone(
                        new_message,
                    )) => match &tls_packet.msg[0] {
                        TlsMessage::Handshake(TlsMessageHandshake::ServerDone(message)) => {
                            assert_eq!(new_message.data, message.to_vec());
                        }
                        _ => unreachable!(),
                    },
                    _ => unreachable!(),
                }
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn valid_server_key_exchange_tls_packet() {
        let mut parsed_packet = ParsedPacket::new(0);
        handle_tls_packet(
            IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10)),
            4444,
            IpAddr::V4(Ipv4Addr::new(11, 11, 11, 11)),
            443,
            SERVER_KEY_EXCHANGE,
            &mut parsed_packet,
        );

        let (_, tls_packet) = parse_tls_plaintext(SERVER_KEY_EXCHANGE).unwrap();
        match parsed_packet.get_application_layer_packet().unwrap() {
            SerializablePacket::TlsPacket(new_tls_packet) => {
                assert_eq!(
                    new_tls_packet.version,
                    format!("{}", tls_packet.hdr.version)
                );
                assert_eq!(new_tls_packet.length, tls_packet.hdr.len);
                assert_eq!(new_tls_packet.messages.len(), tls_packet.msg.len());

                match &new_tls_packet.messages[0] {
                    CustomTlsMessage::Handshake(CustomHandshakeMessage::ServerKeyExchange(
                        new_message,
                    )) => match &tls_packet.msg[0] {
                        TlsMessage::Handshake(TlsMessageHandshake::ServerKeyExchange(message)) => {
                            match &new_message.parameters {
                                ServerParameters::Ecdh(new_params) => {
                                    if let Ok((_, ecdh)) = parse_ecdh_params(message.parameters) {
                                        assert_eq!(
                                            new_params.public_point,
                                            ecdh.public.point.to_vec()
                                        );
                                        assert_eq!(
                                            new_params.curve.ec_type,
                                            ecdh.curve_params.curve_type.to_string()
                                        );

                                        if let CustomEcContent::NamedGroup(new_group) =
                                            &new_params.curve.ec_content
                                        {
                                            if let ECParametersContent::NamedGroup(group) =
                                                &ecdh.curve_params.params_content
                                            {
                                                assert_eq!(new_group.group, format!("{:?}", group))
                                            } else {
                                                unreachable!();
                                            }
                                        } else {
                                            unreachable!();
                                        }
                                    } else {
                                        unreachable!();
                                    }
                                }
                                _ => unreachable!(),
                            }
                        }
                        _ => unreachable!(),
                    },
                    _ => unreachable!(),
                }
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn valid_change_cipher_spec_tls_packet() {
        let mut parsed_packet = ParsedPacket::new(0);
        handle_tls_packet(
            IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10)),
            4444,
            IpAddr::V4(Ipv4Addr::new(11, 11, 11, 11)),
            443,
            CHANGE_CIPHER_SPEC,
            &mut parsed_packet,
        );

        let (_, tls_packet) = parse_tls_plaintext(CHANGE_CIPHER_SPEC).unwrap();
        match parsed_packet.get_application_layer_packet().unwrap() {
            SerializablePacket::TlsPacket(new_tls_packet) => {
                assert_eq!(
                    new_tls_packet.version,
                    format!("{}", tls_packet.hdr.version)
                );
                assert_eq!(new_tls_packet.length, tls_packet.hdr.len);
                assert_eq!(new_tls_packet.messages.len(), tls_packet.msg.len());

                match &new_tls_packet.messages[0] {
                    CustomTlsMessage::ChangeCipherSpec => match tls_packet.msg[0] {
                        TlsMessage::ChangeCipherSpec => assert!(true),
                        _ => unreachable!(),
                    },
                    _ => unreachable!(),
                }
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn valid_client_hello_tls_packet() {
        let mut parsed_packet = ParsedPacket::new(0);
        handle_tls_packet(
            IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10)),
            4444,
            IpAddr::V4(Ipv4Addr::new(11, 11, 11, 11)),
            443,
            CLIENT_HELLO,
            &mut parsed_packet,
        );

        let (_, tls_packet) = parse_tls_plaintext(CLIENT_HELLO).unwrap();
        match parsed_packet.get_application_layer_packet().unwrap() {
            SerializablePacket::TlsPacket(new_tls_packet) => {
                assert_eq!(
                    new_tls_packet.version,
                    format!("{}", tls_packet.hdr.version)
                );
                assert_eq!(new_tls_packet.length, tls_packet.hdr.len);
                assert_eq!(new_tls_packet.messages.len(), tls_packet.msg.len());

                match &new_tls_packet.messages[0] {
                    CustomTlsMessage::Handshake(CustomHandshakeMessage::ClientHello(
                        new_message,
                    )) => match &tls_packet.msg[0] {
                        TlsMessage::Handshake(TlsMessageHandshake::ClientHello(message)) => {
                            assert_eq!(new_message.version, format!("{:?}", message.version));
                            assert_eq!(new_message.rand_time, message.rand_time);
                            assert_eq!(new_message.rand_data, message.rand_data);
                            assert_eq!(
                                new_message.session_id,
                                Some(message.session_id.unwrap().to_vec())
                            );
                            assert_eq!(
                                new_message.ciphers,
                                message
                                    .ciphers
                                    .iter()
                                    .map(|c| format!("{:?}", c))
                                    .collect::<Vec<String>>()
                            );
                            assert_eq!(
                                new_message.compressions,
                                message
                                    .comp
                                    .iter()
                                    .map(|c| format!("{:?}", c))
                                    .collect::<Vec<String>>()
                            );

                            match parse_tls_extensions(message.ext.unwrap_or(b"")) {
                                Ok((_, exts)) => assert_eq!(
                                    new_message.extensions,
                                    parse_custom_tls_extensions(exts)
                                ),
                                _ => unreachable!(),
                            }
                        }
                        _ => unreachable!(),
                    },
                    _ => unreachable!(),
                }
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn valid_client_key_exchange_tls_packet() {
        let mut parsed_packet = ParsedPacket::new(0);
        handle_tls_packet(
            IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10)),
            4444,
            IpAddr::V4(Ipv4Addr::new(11, 11, 11, 11)),
            443,
            CLIENT_KEY_EXCHANGE,
            &mut parsed_packet,
        );

        let (_, tls_packet) = parse_tls_plaintext(CLIENT_KEY_EXCHANGE).unwrap();
        match parsed_packet.get_application_layer_packet().unwrap() {
            SerializablePacket::TlsPacket(new_tls_packet) => {
                assert_eq!(
                    new_tls_packet.version,
                    format!("{}", tls_packet.hdr.version)
                );
                assert_eq!(new_tls_packet.length, tls_packet.hdr.len);
                assert_eq!(new_tls_packet.messages.len(), tls_packet.msg.len());

                match &new_tls_packet.messages[0] {
                    CustomTlsMessage::Handshake(CustomHandshakeMessage::ClientKeyExchange(
                        new_message,
                    )) => match &tls_packet.msg[0] {
                        TlsMessage::Handshake(TlsMessageHandshake::ClientKeyExchange(message)) => {
                            match &new_message.parameters {
                                ClientParameters::Unknown(new_params) => match message {
                                    TlsClientKeyExchangeContents::Unknown(content) => {
                                        assert_eq!(new_params, &content.to_vec())
                                    }
                                    _ => unreachable!(),
                                },
                                _ => unreachable!(),
                            }
                        }
                        _ => unreachable!(),
                    },
                    _ => unreachable!(),
                }
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn valid_certificate_status_tls_packet() {
        let mut parsed_packet = ParsedPacket::new(0);
        handle_tls_packet(
            IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10)),
            4444,
            IpAddr::V4(Ipv4Addr::new(11, 11, 11, 11)),
            443,
            CERTIFICATE_STATUS,
            &mut parsed_packet,
        );

        let (_, tls_packet) = parse_tls_plaintext(CERTIFICATE_STATUS).unwrap();
        match parsed_packet.get_application_layer_packet().unwrap() {
            SerializablePacket::TlsPacket(new_tls_packet) => {
                assert_eq!(
                    new_tls_packet.version,
                    format!("{}", tls_packet.hdr.version)
                );
                assert_eq!(new_tls_packet.length, tls_packet.hdr.len);
                assert_eq!(new_tls_packet.messages.len(), tls_packet.msg.len());

                match &new_tls_packet.messages[0] {
                    CustomTlsMessage::Handshake(CustomHandshakeMessage::CertificateStatus(
                        new_message,
                    )) => match &tls_packet.msg[0] {
                        TlsMessage::Handshake(TlsMessageHandshake::CertificateStatus(message)) => {
                            assert_eq!(new_message.status_type, "OCSP (1)");
                            assert_eq!(new_message.data, message.blob);
                        }
                        _ => unreachable!(),
                    },
                    _ => unreachable!(),
                }
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn valid_alert_tls_packet() {
        let mut parsed_packet = ParsedPacket::new(0);
        handle_tls_packet(
            IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10)),
            4444,
            IpAddr::V4(Ipv4Addr::new(11, 11, 11, 11)),
            443,
            ALERT,
            &mut parsed_packet,
        );

        let (_, tls_packet) = parse_tls_plaintext(ALERT).unwrap();
        match parsed_packet.get_application_layer_packet().unwrap() {
            SerializablePacket::TlsPacket(new_tls_packet) => {
                assert_eq!(
                    new_tls_packet.version,
                    format!("{}", tls_packet.hdr.version)
                );
                assert_eq!(new_tls_packet.length, tls_packet.hdr.len);
                assert_eq!(new_tls_packet.messages.len(), tls_packet.msg.len());

                match &new_tls_packet.messages[0] {
                    CustomTlsMessage::Alert(new_message) => match &tls_packet.msg[0] {
                        TlsMessage::Alert(message) => {
                            assert_eq!(new_message.severity, message.severity.to_string());
                            assert_eq!(new_message.description, message.code.to_string());
                        }
                        _ => unreachable!(),
                    },
                    _ => unreachable!(),
                }
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn unknown_tls_record() {
        let mut parsed_packet = ParsedPacket::new(0);
        handle_tls_packet(
            IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10)),
            4444,
            IpAddr::V4(Ipv4Addr::new(11, 11, 11, 11)),
            443,
            UNKNOWN_RECORD,
            &mut parsed_packet,
        );

        match parsed_packet.get_application_layer_packet().unwrap() {
            SerializablePacket::TlsPacket(new_tls_packet) => {
                assert_eq!(new_tls_packet.version, "");
                assert_eq!(new_tls_packet.length, 0);
                assert_eq!(new_tls_packet.messages.len(), 1);

                match &new_tls_packet.messages[0] {
                    CustomTlsMessage::Malformed(new_message) => {
                        assert_eq!(new_message.version, "Unknown");
                        assert_eq!(new_message.message_type, "Unknown");
                        assert_eq!(new_message.data, UNKNOWN_RECORD);

                        match &new_message.error_type {
                            TlsMalformedError::UnknownRecord(str) => {
                                assert_eq!(str, "Unknown record type");
                            }
                            _ => unreachable!(),
                        }
                    }
                    _ => unreachable!(),
                }
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn too_large_tls_record() {
        let mut parsed_packet = ParsedPacket::new(0);
        handle_tls_packet(
            IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10)),
            4444,
            IpAddr::V4(Ipv4Addr::new(11, 11, 11, 11)),
            443,
            TOO_LARGE_RECORD,
            &mut parsed_packet,
        );

        match parsed_packet.get_application_layer_packet().unwrap() {
            SerializablePacket::TlsPacket(new_tls_packet) => {
                assert_eq!(new_tls_packet.version, "");
                assert_eq!(new_tls_packet.length, 0);
                assert_eq!(new_tls_packet.messages.len(), 1);

                match &new_tls_packet.messages[0] {
                    CustomTlsMessage::Malformed(new_message) => {
                        assert_eq!(new_message.version, "Tls12");
                        assert_eq!(new_message.message_type, "ApplicationData");
                        assert_eq!(new_message.data, TOO_LARGE_RECORD);

                        match &new_message.error_type {
                            TlsMalformedError::LengthTooLarge(str) => {
                                assert_eq!(str, "Max Record size exceeded (RFC8446 5.1)");
                            }
                            _ => unreachable!(),
                        }
                    }
                    _ => unreachable!(),
                }
            }
            _ => unreachable!(),
        }
    }
}
