use std::{
    net::{Ipv4Addr, Ipv6Addr},
    str::from_utf8,
};

use dns_parser::{Header as DnsHeader, Packet as DnsPacket, Question, RData, ResourceRecord};
use httparse::{Request, Response};
use serde::Serialize;
use tls_parser::{
    parse_dh_params, parse_ec_parameters, parse_ecdh_params, parse_tls_extensions, ECParameters,
    ECParametersContent, ECPoint, ExplicitPrimeContent, NamedGroup, ServerDHParams,
    ServerECDHParams, TlsCertificateContents, TlsCertificateRequestContents,
    TlsCertificateStatusContents, TlsClientHelloContents, TlsClientKeyExchangeContents,
    TlsHelloRetryRequestContents, TlsMessageAlert, TlsMessageHeartbeat, TlsNewSessionTicketContent,
    TlsNextProtocolContent, TlsServerHelloContents, TlsServerHelloV13Draft18Contents,
    TlsServerKeyExchangeContents, TlsVersion,
};
use x509_parser::{parse_x509_certificate, prelude::X509Certificate};

#[derive(Serialize, Debug)]
pub enum HttpContentType {
    TextCorrectlyDecoded(String),
    TextMalformedDecoded(String),
    TextDefaultDecoded(String),

    Image(Vec<u8>),
    Unknown(Vec<u8>),
    Encoded(String, Vec<u8>),
    Multipart(Vec<u8>),
    None,
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

/// TLS Packet Representation

#[derive(Serialize, Debug)]
pub struct SerializableTlsPacket {
    pub version: String,
    pub messages: Vec<CustomTlsMessage>,
    pub length: u16,
}

impl SerializableTlsPacket {
    pub fn set_version(&mut self, version: TlsVersion) {
        self.version = format!("{}", version);
    }

    pub fn set_messages(&mut self, messages: Vec<CustomTlsMessage>) {
        self.messages = messages;
    }

    pub fn set_length(&mut self, length: u16) {
        self.length = length;
    }

    pub fn is_default(&self) -> bool {
        self.length == 0 && self.messages.is_empty() && self.version == "".to_owned()
    }
}

impl Default for SerializableTlsPacket {
    fn default() -> Self {
        SerializableTlsPacket {
            version: "".to_owned(),
            messages: vec![],
            length: 0,
        }
    }
}

#[derive(Serialize, Debug)]
#[serde(tag = "type")]
pub enum CustomTlsMessage {
    ChangeCipherSpec,
    Alert(CustomAlertMessage),
    Handshake(CustomHandshakeMessage),
    ApplicationData(CustomApplicationDataMessage),
    Heartbeat(CustomHeartbeatMessage),
    Encrypted(CustomEncryptedMessage),
}

#[derive(Serialize, Debug)]
#[serde(tag = "subType", content = "content")]
pub enum CustomHandshakeMessage {
    ClientHello(ClientHelloMessage),
    ServerHello(ServerHelloMessage),
    Certificate(CertificateMessage),
    CertificateRequest(CertificateRequestMessage),
    CertificateStatus(CertificateStatusMessage),
    CertificateVerify(CertificateVerifyMessage),
    ClientKeyExchange(ClientKeyExchangeMessage),
    EndOfEarlyData,
    Finished(FinishedMessage),
    HelloRequest,
    HelloRetryRequest(HelloRetryRequestMessage),
    KeyUpdate(String),
    NewSessionTicket(NewSessionTicketMessage),
    NextProtocol(NextProtocolMessage),
    ServerDone(ServerDoneMessage),
    ServerHelloV13Draft18(ServerHelloV13Draft18Message),
    ServerKeyExchange(ServerKeyExchangeMessage),
}

#[derive(Serialize, Debug)]
pub struct CustomAlertMessage {
    pub severity: String,
    pub description: String,
}

impl CustomAlertMessage {
    pub fn new(message: &TlsMessageAlert) -> Self {
        CustomAlertMessage {
            severity: message.severity.to_string(),
            description: message.code.to_string(),
        }
    }
}

#[derive(Serialize, Debug)]
pub struct CustomHeartbeatMessage {
    pub heartbeat_type: String,
    pub payload: Vec<u8>,
    pub payload_len: u16,
}

impl CustomHeartbeatMessage {
    pub fn new(message: &TlsMessageHeartbeat) -> Self {
        CustomHeartbeatMessage {
            heartbeat_type: format!("{}", message.heartbeat_type),
            payload: message.payload.to_vec(),
            payload_len: message.payload_len,
        }
    }
}

#[derive(Serialize, Debug)]
pub struct ClientHelloMessage {
    pub version: String,
    pub rand_time: u32,
    pub rand_data: Vec<u8>,
    pub session_id: Option<Vec<u8>>,
    pub ciphers: Vec<String>,
    pub compressions: Vec<String>,
    pub extensions: Vec<String>,
}

impl ClientHelloMessage {
    pub fn new(message: &TlsClientHelloContents) -> Self {
        ClientHelloMessage {
            version: format!("{:?}", message.version),
            rand_time: message.rand_time,
            rand_data: message.rand_data.to_vec(),
            session_id: message.session_id.map_or(None, |v| Some(v.to_vec())),
            ciphers: message.ciphers.iter().map(|c| format!("{:?}", c)).collect(),
            compressions: message.comp.iter().map(|c| format!("{:?}", c)).collect(),
            extensions: match parse_tls_extensions(message.ext.unwrap_or(b"")) {
                Ok((_, exts)) => exts.iter().map(|x| format!("{:?}", x)).collect(),
                Err(_) => vec!["Error parsing".to_owned()],
            },
        }
    }
}

#[derive(Serialize, Debug)]
pub struct ServerHelloMessage {
    pub version: String,
    pub rand_time: u32,
    pub rand_data: Vec<u8>,
    pub session_id: Option<Vec<u8>>,
    pub cipher: String,
    pub compression: String,
    pub extensions: Vec<String>,
}

impl ServerHelloMessage {
    pub fn new(message: &TlsServerHelloContents) -> Self {
        ServerHelloMessage {
            version: format!("{:?}", message.version),
            rand_time: message.rand_time,
            rand_data: message.rand_data.to_vec(),
            session_id: message.session_id.map_or(None, |v| Some(v.to_vec())),
            cipher: format!("{:?}", message.cipher),
            compression: format!("{:?}", message.compression),
            extensions: match parse_tls_extensions(message.ext.unwrap_or(b"")) {
                Ok((_, exts)) => exts.iter().map(|x| format!("{:?}", x)).collect(),
                Err(_) => vec!["Error parsing".to_owned()],
            },
        }
    }
}

#[derive(Serialize, Debug)]
pub struct Certificate {
    pub signature_algorithm: String,
    pub signature_value: Vec<u8>,

    pub serial: String,
    pub issuer_uid: String,
    pub subject: String,
    pub subject_uid: String,
    // pub subject_pki: String,
    pub validity: String,
    pub version: String,
}

impl Certificate {
    fn new(cert: &X509Certificate) -> Self {
        Certificate {
            signature_algorithm: cert.signature_algorithm.oid().to_id_string(),
            signature_value: cert.signature_value.data.to_vec(),
            serial: cert.serial.to_string(),
            issuer_uid: if let Some(issuer) = &cert.issuer_uid {
                format!("{:?}", issuer)
            } else {
                "-".to_owned()
            },
            subject: cert.subject.to_string(),
            subject_uid: if let Some(subject) = &cert.subject_uid {
                format!("{:?}", subject)
            } else {
                "-".to_owned()
            },
            // subject_pki: ,
            validity: format!(
                "NotBefore: {}, NotAfter: {}",
                cert.validity.not_before, cert.validity.not_after
            ),
            version: cert.version.to_string(),
        }
    }
}

#[derive(Serialize, Debug)]
pub struct CertificateMessage {
    pub certificates: Vec<Certificate>,
}

impl CertificateMessage {
    pub fn new(message: &TlsCertificateContents) -> Self {
        CertificateMessage {
            certificates: message
                .cert_chain
                .iter()
                .map(|c| {
                    let cert = parse_x509_certificate(c.data);
                    if let Ok((_, cert)) = cert {
                        Some(Certificate::new(&cert))
                    } else {
                        None
                    }
                })
                .flatten()
                .collect(),
        }
    }
}

#[derive(Serialize, Debug)]
pub struct CertificateRequestMessage {
    pub sig_hash_algos: Vec<u16>,
}

impl CertificateRequestMessage {
    pub fn new(message: &TlsCertificateRequestContents) -> Self {
        CertificateRequestMessage {
            sig_hash_algos: message
                .sig_hash_algs
                .as_ref()
                .unwrap_or(&Vec::new())
                .to_vec(),
        }
    }
}

// TODO: CertificateStatusMessage
#[derive(Serialize, Debug)]
pub struct CertificateStatusMessage {
    pub status_type: String,
    pub data: Vec<u8>,
}

impl CertificateStatusMessage {
    pub fn new(packet: &TlsCertificateStatusContents) -> Self {
        CertificateStatusMessage {
            status_type: match packet.status_type {
                1 => "OCSP (1)".to_owned(),
                n => format!("Unknown ({})", n),
            },
            data: packet.blob.to_vec(),
        }
    }
}

#[derive(Serialize, Debug)]
pub struct CertificateVerifyMessage {
    pub data: Vec<u8>,
}

impl CertificateVerifyMessage {
    pub fn new(message: &[u8]) -> Self {
        CertificateVerifyMessage {
            data: message.to_vec(),
        }
    }
}

#[derive(Serialize, Debug)]
#[serde(tag = "type", content = "parameters")]
pub enum ClientParameters {
    Dh(ServerDhParameters),
    Ec(ServerEcParameters),
    Ecdh(ClientEcdhParameters),
    Unknown(Vec<u8>),
}

#[derive(Serialize, Debug)]
pub struct ClientEcdhParameters {
    pub point: Vec<u8>,
}

impl ClientEcdhParameters {
    pub fn new(ec: &ECPoint) -> Self {
        ClientEcdhParameters {
            point: ec.point.to_vec(),
        }
    }
}

#[derive(Serialize, Debug)]
pub struct ClientKeyExchangeMessage {
    pub parameters: ClientParameters,
}

impl ClientKeyExchangeMessage {
    pub fn new(message: &TlsClientKeyExchangeContents) -> Self {
        match message {
            TlsClientKeyExchangeContents::Dh(dh) => {
                return ClientKeyExchangeMessage {
                    parameters: ClientParameters::Dh(ServerDhParameters::new(
                        &parse_dh_params(dh).unwrap().1,
                    )),
                }
            }
            TlsClientKeyExchangeContents::Ecdh(ecdh) => {
                return ClientKeyExchangeMessage {
                    parameters: ClientParameters::Ecdh(ClientEcdhParameters::new(ecdh)),
                }
            }
            TlsClientKeyExchangeContents::Unknown(content) => {
                if let Ok((_, ec)) = parse_ec_parameters(content) {
                    return ClientKeyExchangeMessage {
                        parameters: ClientParameters::Ec(ServerEcParameters::new(&ec)),
                    };
                }

                return ClientKeyExchangeMessage {
                    parameters: ClientParameters::Unknown(content.to_vec()),
                };
            }
        }
    }
}

#[derive(Serialize, Debug)]
pub struct FinishedMessage {
    pub data: Vec<u8>,
}

impl FinishedMessage {
    pub fn new(message: &[u8]) -> Self {
        FinishedMessage {
            data: message.to_vec(),
        }
    }
}

#[derive(Serialize, Debug)]
pub struct HelloRetryRequestMessage {
    pub cipher: String,
    pub extensions: Vec<String>,
    pub version: String,
}

impl HelloRetryRequestMessage {
    pub fn new(message: &TlsHelloRetryRequestContents) -> Self {
        HelloRetryRequestMessage {
            cipher: format!("{:?}", message.cipher),
            extensions: match parse_tls_extensions(message.ext.unwrap_or(b"")) {
                Ok((_, exts)) => exts.iter().map(|x| format!("{:?}", x)).collect(),
                Err(_) => vec!["Error parsing".to_owned()],
            },
            version: format!("{}", message.version),
        }
    }
}

#[derive(Serialize, Debug)]
pub struct NewSessionTicketMessage {
    pub ticket: Vec<u8>,
    pub ticket_lifetime_hint: u32,
}

impl NewSessionTicketMessage {
    pub fn new(message: &TlsNewSessionTicketContent) -> Self {
        NewSessionTicketMessage {
            ticket: message.ticket.to_vec(),
            ticket_lifetime_hint: message.ticket_lifetime_hint,
        }
    }
}

#[derive(Serialize, Debug)]
pub struct NextProtocolMessage {
    pub selected_protocol: Vec<u8>,
    pub padding: Vec<u8>,
}

impl NextProtocolMessage {
    pub fn new(message: &TlsNextProtocolContent) -> Self {
        NextProtocolMessage {
            selected_protocol: message.selected_protocol.to_vec(),
            padding: message.padding.to_vec(),
        }
    }
}

#[derive(Serialize, Debug)]
pub struct ServerDoneMessage {
    pub data: Vec<u8>,
}

impl ServerDoneMessage {
    pub fn new(message: &[u8]) -> Self {
        ServerDoneMessage {
            data: message.to_vec(),
        }
    }
}

#[derive(Serialize, Debug)]
pub struct ServerHelloV13Draft18Message {
    pub version: String,
    pub random: Vec<u8>,
    pub cipher: String,
    pub extensions: Vec<String>,
}

impl ServerHelloV13Draft18Message {
    pub fn new(message: &TlsServerHelloV13Draft18Contents) -> Self {
        ServerHelloV13Draft18Message {
            version: format!("{:?}", message.version),
            random: message.random.to_vec(),
            cipher: format!("{:?}", message.cipher),
            extensions: match parse_tls_extensions(message.ext.unwrap_or(b"")) {
                Ok((_, exts)) => exts.iter().map(|x| format!("{:?}", x)).collect(),
                Err(_) => vec!["Error parsing".to_owned()],
            },
        }
    }
}

#[derive(Serialize, Debug)]
#[serde(tag = "type", content = "parameters")]
pub enum ServerParameters {
    Dh(ServerDhParameters),
    Ec(ServerEcParameters),
    Ecdh(ServerEcdhParameters),
    Unknown(Vec<u8>),
}

#[derive(Serialize, Debug)]
pub struct ServerEcdhParameters {
    pub public_point: Vec<u8>,
    pub curve: ServerEcParameters,
}

impl ServerEcdhParameters {
    pub fn new(params: &ServerECDHParams) -> Self {
        ServerEcdhParameters {
            public_point: params.public.point.to_vec(),
            curve: ServerEcParameters::new(&params.curve_params),
        }
    }
}

#[derive(Serialize, Debug)]
pub struct ServerDhParameters {
    pub prime_modulus: Vec<u8>,
    pub generator: Vec<u8>,
    pub public_value: Vec<u8>,
}

impl ServerDhParameters {
    fn new(params: &ServerDHParams) -> Self {
        ServerDhParameters {
            prime_modulus: params.dh_p.to_vec(),
            generator: params.dh_g.to_vec(),
            public_value: params.dh_ys.to_vec(),
        }
    }
}

#[derive(Serialize, Debug)]
pub enum CustomEcContent {
    ExplicitPrime(CustomExplicitPrime),
    NamedGroup(CustomNamedGroup),
}

#[derive(Serialize, Debug)]
pub struct CustomNamedGroup {
    pub group: String,
}

impl CustomNamedGroup {
    fn new(group: &NamedGroup) -> Self {
        CustomNamedGroup {
            group: format!("{:?}", group),
        }
    }
}

#[derive(Serialize, Debug)]
pub struct CustomExplicitPrime {
    pub prime_p: Vec<u8>,
    pub curve: (Vec<u8>, Vec<u8>),
    pub base_point: Vec<u8>,
    pub order: Vec<u8>,
    pub cofactor: Vec<u8>,
}

impl CustomExplicitPrime {
    fn new(content: &ExplicitPrimeContent) -> Self {
        CustomExplicitPrime {
            prime_p: content.prime_p.to_vec(),
            curve: (content.curve.a.to_vec(), content.curve.b.to_vec()),
            base_point: content.base.point.to_vec(),
            order: content.order.to_vec(),
            cofactor: content.cofactor.to_vec(),
        }
    }
}

#[derive(Serialize, Debug)]
pub struct ServerEcParameters {
    pub ec_type: String,
    pub ec_content: CustomEcContent,
}

impl ServerEcParameters {
    fn new(params: &ECParameters) -> Self {
        ServerEcParameters {
            ec_type: params.curve_type.to_string(),
            ec_content: match &params.params_content {
                ECParametersContent::ExplicitPrime(content) => {
                    CustomEcContent::ExplicitPrime(CustomExplicitPrime::new(&content))
                }
                ECParametersContent::NamedGroup(content) => {
                    CustomEcContent::NamedGroup(CustomNamedGroup::new(&content))
                }
            },
        }
    }
}

#[derive(Serialize, Debug)]
pub struct ServerKeyExchangeMessage {
    pub parameters: ServerParameters,
}

impl ServerKeyExchangeMessage {
    pub fn new(message: &TlsServerKeyExchangeContents) -> Self {
        if let Ok((_, ecdh)) = parse_ecdh_params(message.parameters) {
            return ServerKeyExchangeMessage {
                parameters: ServerParameters::Ecdh(ServerEcdhParameters::new(&ecdh)),
            };
        }

        if let Ok((_, dh)) = parse_dh_params(message.parameters) {
            return ServerKeyExchangeMessage {
                parameters: ServerParameters::Dh(ServerDhParameters::new(&dh)),
            };
        }

        if let Ok((_, ec)) = parse_ec_parameters(message.parameters) {
            return ServerKeyExchangeMessage {
                parameters: ServerParameters::Ec(ServerEcParameters::new(&ec)),
            };
        }

        return ServerKeyExchangeMessage {
            parameters: ServerParameters::Unknown(message.parameters.to_vec()),
        };
    }
}

#[derive(Serialize, Debug)]
pub struct CustomEncryptedMessage {
    pub data: Vec<u8>,
}

impl CustomEncryptedMessage {
    pub fn new(message: &[u8]) -> Self {
        CustomEncryptedMessage {
            data: message.to_vec(),
        }
    }
}

#[derive(Serialize, Debug)]
pub struct CustomApplicationDataMessage {
    pub data: Vec<u8>,
}

impl CustomApplicationDataMessage {
    pub fn new(message: &[u8]) -> Self {
        CustomApplicationDataMessage {
            data: message.to_vec(),
        }
    }
}

/// DNS Packet Rapresentation

#[derive(Serialize, Debug)]
pub struct SerializableDnsPacket {
    pub header: CustomDnsHeader,
    pub questions: Vec<CustomQuestion>,
    pub answers: Vec<CustomResourceRecord>,
    pub nameservers: Vec<CustomResourceRecord>,
    pub additional: Vec<CustomResourceRecord>,
}

impl<'a> From<&DnsPacket<'a>> for SerializableDnsPacket {
    fn from(dns_packet: &DnsPacket<'a>) -> Self {
        SerializableDnsPacket {
            header: CustomDnsHeader::from(&dns_packet.header),
            questions: dns_packet
                .questions
                .iter()
                .map(|q| CustomQuestion::from(q))
                .collect(),
            answers: dns_packet
                .answers
                .iter()
                .map(|r| CustomResourceRecord::from(r))
                .collect(),
            nameservers: dns_packet
                .nameservers
                .iter()
                .map(|r| CustomResourceRecord::from(r))
                .collect(),
            additional: dns_packet
                .additional
                .iter()
                .map(|r| CustomResourceRecord::from(r))
                .collect(),
        }
    }
}

#[derive(Serialize, Debug)]
pub struct CustomQuestion {
    pub query_name: String,
    pub prefer_unicast: bool,
    pub query_type: String,
    pub query_class: String,
}

impl From<&Question<'_>> for CustomQuestion {
    fn from(question: &Question<'_>) -> Self {
        CustomQuestion {
            query_name: question.qname.to_string(),
            prefer_unicast: question.prefer_unicast,
            query_type: format!("{:?}", question.qtype),
            query_class: format!("{:?}", question.qclass),
        }
    }
}

#[derive(Serialize, Debug)]
pub struct CustomDnsHeader {
    pub id: u16,
    pub query: bool,
    pub opcode: String,
    pub authoritative: bool,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub authenticated_data: bool,
    pub checking_disabled: bool,
    pub response_code: String,
    pub num_questions: u16,
    pub num_answers: u16,
    pub num_nameservers: u16,
    pub num_additional: u16,
}

impl From<&DnsHeader> for CustomDnsHeader {
    fn from(header: &DnsHeader) -> Self {
        CustomDnsHeader {
            id: header.id,
            query: header.query,
            opcode: format!("{:?}", header.opcode),
            authoritative: header.authoritative,
            truncated: header.truncated,
            recursion_desired: header.recursion_desired,
            recursion_available: header.recursion_available,
            authenticated_data: header.authenticated_data,
            checking_disabled: header.checking_disabled,
            response_code: format!("{:?}", header.response_code),
            num_questions: header.questions,
            num_answers: header.answers,
            num_nameservers: header.nameservers,
            num_additional: header.additional,
        }
    }
}

#[derive(Serialize, Debug)]
pub struct CustomResourceRecord {
    pub name: String,
    pub multicast_unique: bool,
    pub class: String,
    pub ttl: u32,
    pub data: CustomResourceData,
}

impl From<&ResourceRecord<'_>> for CustomResourceRecord {
    fn from(rr: &ResourceRecord<'_>) -> Self {
        CustomResourceRecord {
            name: rr.name.to_string(),
            multicast_unique: rr.multicast_unique,
            class: format!("{:?}", rr.cls),
            ttl: rr.ttl,
            data: CustomResourceData::from(&rr.data),
        }
    }
}

#[derive(Serialize, Debug)]
#[serde(tag = "type")]
pub enum CustomResourceData {
    A(A),
    AAAA(Aaaa),
    CNAME(Cname),
    MX(Mx),
    NS(Ns),
    PTR(Ptr),
    SOA(Soa),
    SRV(Srv),
    TXT(Txt),
    Unknown(Unknown),
}

impl From<&RData<'_>> for CustomResourceData {
    fn from(data: &RData<'_>) -> Self {
        match data {
            RData::A(a) => CustomResourceData::A(A { address: a.0 }),
            RData::AAAA(aaaa) => CustomResourceData::AAAA(Aaaa { address: aaaa.0 }),
            RData::CNAME(cname) => CustomResourceData::CNAME(Cname {
                name: cname.0.to_string(),
            }),
            RData::MX(mx) => CustomResourceData::MX(Mx {
                preference: mx.preference,
                exchange: mx.preference.to_string(),
            }),
            RData::NS(ns) => CustomResourceData::NS(Ns {
                name: ns.0.to_string(),
            }),
            RData::PTR(ptr) => CustomResourceData::PTR(Ptr {
                name: ptr.0.to_string(),
            }),
            RData::SOA(soa) => CustomResourceData::SOA(Soa {
                primary_ns: soa.primary_ns.to_string(),
                mailbox: soa.mailbox.to_string(),
                serial: soa.serial,
                refresh: soa.refresh,
                retry: soa.retry,
                expire: soa.expire,
                minimum_ttl: soa.minimum_ttl,
            }),
            RData::SRV(srv) => CustomResourceData::SRV(Srv {
                priority: srv.priority,
                weight: srv.weight,
                port: srv.port,
                target: srv.target.to_string(),
            }),
            RData::TXT(txt) => CustomResourceData::TXT(Txt {
                data: txt.iter().fold(vec![], |mut acc, x| {
                    acc.extend_from_slice(x);
                    acc
                }),
            }),
            RData::Unknown(unknown) => CustomResourceData::Unknown(Unknown {
                data: unknown.to_vec(),
            }),
        }
    }
}

#[derive(Serialize, Debug)]
pub struct A {
    pub address: Ipv4Addr,
}

#[derive(Serialize, Debug)]
pub struct Aaaa {
    pub address: Ipv6Addr,
}
#[derive(Serialize, Debug)]
pub struct Cname {
    pub name: String,
}
#[derive(Serialize, Debug)]
pub struct Mx {
    pub preference: u16,
    pub exchange: String,
}
#[derive(Serialize, Debug)]
pub struct Ns {
    pub name: String,
}
#[derive(Serialize, Debug)]
pub struct Ptr {
    pub name: String,
}

#[derive(Serialize, Debug)]
pub struct Soa {
    pub primary_ns: String,
    pub mailbox: String,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum_ttl: u32,
}

#[derive(Serialize, Debug)]
pub struct Srv {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: String,
}

#[derive(Serialize, Debug)]
pub struct Txt {
    pub data: Vec<u8>,
}

#[derive(Serialize, Debug)]
pub struct Unknown {
    pub data: Vec<u8>,
}
