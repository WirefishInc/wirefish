use std::str::from_utf8;

use httparse::{Request, Response};
use serde::Serialize;
use tls_parser::{
    parse_dh_params, parse_tls_extensions, TlsCertificateContents, TlsCertificateRequestContents,
    TlsCertificateStatusContents, TlsClientHelloContents, TlsClientKeyExchangeContents,
    TlsHelloRetryRequestContents, TlsMessageAlert, TlsMessageHeartbeat, TlsNewSessionTicketContent,
    TlsNextProtocolContent, TlsServerHelloContents, TlsServerHelloV13Draft18Contents,
    TlsServerKeyExchangeContents, TlsVersion,
};
use x509_parser::{parse_x509_certificate, prelude::X509Certificate};

#[derive(Serialize, Debug)]
#[serde(tag = "type", content = "content")]
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
pub struct CertificateStatusMessage {}

impl CertificateStatusMessage {
    pub fn new(_: &TlsCertificateStatusContents) -> Self {
        CertificateStatusMessage {}
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
pub struct ClientKeyExchangeMessage {
    pub algo_type: String,
    pub data: Vec<u8>,
}

impl ClientKeyExchangeMessage {
    pub fn new(message: &TlsClientKeyExchangeContents) -> Self {
        let algo_type: String;
        let data: Vec<u8>;

        match message {
            TlsClientKeyExchangeContents::Dh(key) => {
                algo_type = "Diffie-Hellman".to_owned();
                data = key.to_vec();
            }
            TlsClientKeyExchangeContents::Ecdh(point) => {
                algo_type = "ECDH".to_owned();
                data = point.point.to_vec();
            }
            TlsClientKeyExchangeContents::Unknown(some_data) => {
                algo_type = "Unknown".to_owned();
                data = some_data.to_vec();
            }
        };

        ClientKeyExchangeMessage { algo_type, data }
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
pub struct ServerKeyExchangeMessage {
    pub prime_modulus: Vec<u8>,
    pub generator: Vec<u8>,
    pub public_value: Vec<u8>,
}

impl ServerKeyExchangeMessage {
    pub fn new(message: &TlsServerKeyExchangeContents) -> Self {
        let prime_modulus: Vec<u8>;
        let generator: Vec<u8>;
        let public_value: Vec<u8>;

        let dh = parse_dh_params(message.parameters);
        if let Ok((_, dh)) = dh {
            prime_modulus = dh.dh_p.to_vec();
            generator = dh.dh_g.to_vec();
            public_value = dh.dh_ys.to_vec();
        } else {
            prime_modulus = Vec::new();
            generator = Vec::new();
            public_value = Vec::new();
        }

        ServerKeyExchangeMessage {
            prime_modulus,
            generator,
            public_value,
        }
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
