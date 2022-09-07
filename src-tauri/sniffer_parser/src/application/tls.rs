use std::net::IpAddr;

use tls_parser::{parse_tls_raw_record, TlsRecordType, parse_tls_encrypted, parse_tls_record_with_header, TlsMessage, TlsMessageHandshake};

use crate::ACTIVE_TLS_PARSERS;
use crate::serializable_packet::ParsedPacket;
use crate::serializable_packet::SerializablePacket;
use crate::serializable_packet::application::*;

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

        ////////////////////////////
        
        let mut tls_packet = SerializableTlsPacket::default();
        let mut custom_messages = vec![];

        while !current_payload.is_empty() {
            let result = parse_tls_raw_record(current_payload);
            match result {
                Ok((_, record)) => {

                    match record.hdr.record_type {
                        TlsRecordType::ApplicationData => {
                            let result = parse_tls_encrypted(current_payload);
                            match result {
                                Ok((rem, record)) => {
                                    println!(
                                        "[]: TLS Encrypted Packet: {}:{} > {}:{}; Version: {}, Record Type: {:?}, Len: {}",
                                        source_ip, source_port, dest_ip, dest_port, record.hdr.version, record.hdr.record_type, record.hdr.len
                                    );

                                    custom_messages.push(CustomTlsMessage::Encrypted(
                                        CustomEncryptedMessage::new(record.msg.blob)
                                    ));

                                    if rem.is_empty() {
                                        tls_packet.set_version(record.hdr.version);
                                        tls_packet.set_messages(custom_messages);
                                        tls_packet.set_length(record.hdr.len);

                                        parsers.remove(&((source_ip, source_port), (dest_ip, dest_port)));
                                        break;
                                    } else {
                                        let end = current_payload.len() - rem.len();
                                        current_payload.drain(..end);
                                        continue;
                                    }
                                }
                                Err(tls_parser::nom::Err::Incomplete(needed)) => {
                                    println!("[ERROR] Incomplete TLS: {:?}", needed);
                                    parsers.remove(&((source_ip, source_port), (dest_ip, dest_port)));
                                    break;
                                }
                                Err(tls_parser::nom::Err::Error(e)) => {
                                    println!("[ERROR] Malformed TLS: {:?}", e.code);
                                    parsers.remove(&((source_ip, source_port), (dest_ip, dest_port)));
                                    break;
                                }
                                Err(tls_parser::nom::Err::Failure(_)) => {
                                    println!("[FAILURE] Malformed TLS");
                                    parsers.remove(&((source_ip, source_port), (dest_ip, dest_port)));
                                    break;
                                }
                            }
                        },
                        _ =>  {
                            let result = parse_tls_record_with_header(record.data, &record.hdr);
                            match result {
                                Ok((rem, messages)) => {
                                    for (i, msg) in messages.iter().enumerate() {
                                        println!(
                                            "[{i}]: TLS Record Packet: {}:{} > {}:{}; Version: {}, Record Type: {:?}, Len: {}, Payload: {:?}",
                                            source_ip, source_port, dest_ip, dest_port, record.hdr.version, record.hdr.record_type, record.hdr.len, msg
                                        );
                                    }

                                    parse_messages(messages, &mut custom_messages);

                                    if rem.is_empty() {
                                        tls_packet.set_version(record.hdr.version);
                                        tls_packet.set_messages(custom_messages);
                                        tls_packet.set_length(record.hdr.len);
        
                                        parsers.remove(&((source_ip, source_port), (dest_ip, dest_port)));
                                        break;
                                    } else {
                                        let end = current_payload.len() - rem.len();
                                        current_payload.drain(..end);
                                    }
                                },
                                Err(tls_parser::nom::Err::Incomplete(_)) => {
                                    // Needs defragmentation
                                    break;
                                },
                                Err(tls_parser::nom::Err::Error(e)) => {
                                    println!("[ERROR] Malformed TLS: {:?}", e.code);
                                    parsers.remove(&((source_ip, source_port), (dest_ip, dest_port)));
                                    break;
                                }
                                Err(tls_parser::nom::Err::Failure(_)) => {
                                    println!("[FAILURE] Malformed TLS");
                                    parsers.remove(&((source_ip, source_port), (dest_ip, dest_port)));
                                    break;
                                }
                            };
                        }
                    }
                },
                Err(tls_parser::nom::Err::Incomplete(_)) => {
                    break;
                },
                Err(tls_parser::nom::Err::Error(e)) => {
                    println!("[INFO - ERROR] {}:{} > {}:{}; Malformed TLS: {:?}", source_ip, source_port, dest_ip, dest_port, e.code);
                    parsers.remove(&((source_ip, source_port), (dest_ip, dest_port)));
                    break;
                }
                Err(tls_parser::nom::Err::Failure(_)) => {
                    println!("[INFO - FAILURE] Malformed TLS");
                    parsers.remove(&((source_ip, source_port), (dest_ip, dest_port)));
                    break;
                }
            }
        }

        if !tls_packet.is_default() {
            parsed_packet.set_application_layer_packet(Some(
                SerializablePacket::TlsPacket(
                    tls_packet
                ),
            ));
        }
    });
}

fn parse_messages(messages: Vec<TlsMessage>, custom_messages: &mut Vec<CustomTlsMessage>) {
    for msg in &messages {
        match msg {
            TlsMessage::Handshake(msg) => {
                match msg {
                    TlsMessageHandshake::ClientHello(msg) => {
                        custom_messages.push(CustomTlsMessage::Handshake(
                            CustomHandshakeMessage::ClientHello(ClientHelloMessage::new(msg))
                        ));
                    },
                    TlsMessageHandshake::ServerHello(msg) => {
                        custom_messages.push(CustomTlsMessage::Handshake(
                            CustomHandshakeMessage::ServerHello(ServerHelloMessage::new(msg))
                        ));
                    },
                    TlsMessageHandshake::Certificate(msg) => {
                        custom_messages.push(CustomTlsMessage::Handshake(
                            CustomHandshakeMessage::Certificate(CertificateMessage::new(msg))
                        ));
                    },
                    TlsMessageHandshake::CertificateRequest(msg) => {
                        custom_messages.push(CustomTlsMessage::Handshake(
                            CustomHandshakeMessage::CertificateRequest(CertificateRequestMessage::new(msg))
                        ));
                    },
                    TlsMessageHandshake::CertificateStatus(msg) => {
                        custom_messages.push(CustomTlsMessage::Handshake(
                            CustomHandshakeMessage::CertificateStatus(CertificateStatusMessage::new(msg))
                        ));
                    },
                    TlsMessageHandshake::CertificateVerify(msg) => {
                        custom_messages.push(CustomTlsMessage::Handshake(
                            CustomHandshakeMessage::CertificateVerify(CertificateVerifyMessage::new(msg))
                        ));
                    },
                    TlsMessageHandshake::ClientKeyExchange(msg) => {
                        custom_messages.push(CustomTlsMessage::Handshake(
                            CustomHandshakeMessage::ClientKeyExchange(ClientKeyExchangeMessage::new(msg))
                        ));
                    },
                    TlsMessageHandshake::EndOfEarlyData => {
                        custom_messages.push(CustomTlsMessage::Handshake(CustomHandshakeMessage::EndOfEarlyData));
                    },
                    TlsMessageHandshake::Finished(msg) => {
                        custom_messages.push(CustomTlsMessage::Handshake(
                            CustomHandshakeMessage::CertificateVerify(CertificateVerifyMessage::new(msg))
                        ));
                    },
                    TlsMessageHandshake::HelloRequest => {
                        custom_messages.push(CustomTlsMessage::Handshake(CustomHandshakeMessage::HelloRequest));
                    },
                    TlsMessageHandshake::HelloRetryRequest(msg) => {
                        custom_messages.push(CustomTlsMessage::Handshake(
                            CustomHandshakeMessage::HelloRetryRequest(HelloRetryRequestMessage::new(msg))
                        ));
                    },
                    TlsMessageHandshake::KeyUpdate(msg) => {
                        custom_messages.push(CustomTlsMessage::Handshake(
                            CustomHandshakeMessage::KeyUpdate(match msg {
                                0x0 => "0x0: Requested".to_owned(),
                                0x1 => "0x1: Not Requested".to_owned(),
                                x => format!("{}: Unknown", x),
                            }
                        )));
                    },
                    TlsMessageHandshake::NewSessionTicket(msg) => {
                        custom_messages.push(CustomTlsMessage::Handshake(
                            CustomHandshakeMessage::NewSessionTicket(NewSessionTicketMessage::new(msg))
                        ));
                    },
                    TlsMessageHandshake::NextProtocol(msg) => {
                        custom_messages.push(CustomTlsMessage::Handshake(
                            CustomHandshakeMessage::NextProtocol(NextProtocolMessage::new(msg))
                        ));
                    },
                    TlsMessageHandshake::ServerDone(msg) => {
                        custom_messages.push(CustomTlsMessage::Handshake(
                            CustomHandshakeMessage::ServerDone(ServerDoneMessage::new(msg))
                        ));
                    },
                    TlsMessageHandshake::ServerHelloV13Draft18(msg) => {
                        custom_messages.push(CustomTlsMessage::Handshake(
                            CustomHandshakeMessage::ServerHelloV13Draft18(ServerHelloV13Draft18Message::new(msg))
                        ));
                    },
                    TlsMessageHandshake::ServerKeyExchange(msg) => {
                        custom_messages.push(CustomTlsMessage::Handshake(
                            CustomHandshakeMessage::ServerKeyExchange(ServerKeyExchangeMessage::new(msg))
                        ));
                    }
                }
            },
            TlsMessage::Alert(msg) => {
                custom_messages.push(CustomTlsMessage::Alert(CustomAlertMessage::new(msg)));
            },
            TlsMessage::Heartbeat(msg) => {
                custom_messages.push(CustomTlsMessage::Heartbeat(CustomHeartbeatMessage::new(msg)));    
            },
            TlsMessage::ChangeCipherSpec => {
                custom_messages.push(CustomTlsMessage::ChangeCipherSpec);
            },
            TlsMessage::ApplicationData(msg) => {
                custom_messages.push(CustomTlsMessage::ApplicationData(CustomApplicationDataMessage::new(msg.blob)));
            }
        }
    }
}