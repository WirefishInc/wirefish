use self::data::{SourceDestination, PacketExchange};
use std::io::{self, Write, BufWriter};
use std::fs::{self, OpenOptions};
use std::collections::HashMap;
use std::path::Path;
use std::ffi::OsStr;
use chrono::Local;
use human_bytes::human_bytes;

const MAX_IP_LEN: usize = 40;
const MAX_PORT_LEN: usize = 20;
const MAX_TIME_LEN: usize = 24;
const MAX_BYTES_LEN: usize = 16;

/// Appends data to a report file, creates the file if it doesn't exist
pub fn write_report(output_path: &str, data: &mut HashMap<SourceDestination, PacketExchange>, first_generation: bool) -> Result<bool, io::Error> {
    let path = Path::new(&output_path);
    let mut file_exists = path.is_file();
    let file_extension = path.extension();

    // Check file extension is .txt
    if file_extension.is_none() || file_extension.and_then(OsStr::to_str).unwrap() != "txt" {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Provide a .txt file"));
    }

    if !file_exists {
        // Create parent directories if they don't exist
        let parent_directory = path.parent().unwrap();
        if !parent_directory.is_dir() {
            fs::create_dir_all(parent_directory)?;
        }
    } else if first_generation {
        // Remove old report file
        fs::remove_file(&output_path)?;
        file_exists = false;
    }

    // Open file in append mode, create it if it doesn't exist
    let file = OpenOptions::new()
        .append(true)
        .create(!file_exists)
        .open(path)?;
    let mut writer = BufWriter::new(file);

    // Write report metadata
    let transmitted_bytes = match data.values().map(|exchange| exchange.transmitted_bytes).reduce(|accum, item| accum + item) {
        Some(bytes) => bytes,
        None => 0
    };
    writer.write_all(("-".repeat(50) + "\n\n").as_bytes())?;
    writer.write_all((">> Updated at: ".to_owned() + &Local::now().format("%Y-%m-%d %H:%M:%S").to_string() + "\n").as_bytes())?;
    writer.write_all((">> Number of Source-Destination pairs: ".to_owned() + &data.len().to_string() + "\n").as_bytes())?;
    writer.write_all((">> Total Bytes transmitted: ".to_owned() + &human_bytes(transmitted_bytes as f64) + "\n\n").as_bytes())?;

    let mut data_pairs = data.drain().peekable();

    if data_pairs.peek().is_some() {

        // Write headers
        let headers = [
            ("Source Ip", MAX_IP_LEN),
            ("Destination Ip", MAX_IP_LEN),
            ("Source Port", MAX_PORT_LEN),
            ("Destination Port", MAX_PORT_LEN),
            ("First Data Exchange", MAX_TIME_LEN),
            ("Last Data Exchange", MAX_TIME_LEN),
            ("Data Exchanged", MAX_BYTES_LEN),
            ("Protocols", 9),
        ];
        for header in headers {
            let len = header.0.len();
            writer.write_all((header.0.to_owned() + "\t" + &tab_word(len, header.1)).as_bytes())?;
        }
        writer.write_all("\n".as_bytes())?;

        // Write packets exchange data
        for (source_destination, exchange) in data_pairs {
            writer.write_all((source_destination.to_string() + "\t" + &exchange.to_string() + "\n").as_bytes())?
        }
        writer.write_all(b"\n")?;
    }

    Ok(true)
}

pub fn tab_word(word_length: usize, fill_length: usize) -> String {
    "\t".repeat(((fill_length - word_length) as f64 / 4 as f64).ceil() as usize)
}

pub mod data {
    use std::collections::HashSet;
    use chrono::{DateTime, Local};
    use std::cmp;
    use crate::report::{MAX_IP_LEN, MAX_PORT_LEN, MAX_BYTES_LEN, MAX_TIME_LEN, tab_word};
    use human_bytes::human_bytes;

    #[derive(PartialEq, Eq, Hash, Debug)]
    pub struct SourceDestination {
        ip_source: String,
        ip_destination: String,
        port_source: String,
        port_destination: String,
    }

    #[derive(Debug)]
    pub struct PacketExchange {
        protocols: HashSet<String>,
        pub transmitted_bytes: usize,
        first_exchange: DateTime<Local>,
        last_exchange: DateTime<Local>,
    }

    impl SourceDestination {
        pub fn new(ip_source: String, ip_destination: String, port_source: String, port_destination: String) -> Self {
            SourceDestination {
                ip_source,
                ip_destination,
                port_source,
                port_destination,
            }
        }
    }

    impl ToString for SourceDestination {
        fn to_string(&self) -> String {
            [
                self.ip_source.clone() + &tab_word(self.ip_source.len(), MAX_IP_LEN),
                self.ip_destination.clone() + &tab_word(self.ip_destination.len(), MAX_IP_LEN),
                self.port_source.clone() + &tab_word(self.port_source.len(), MAX_PORT_LEN),
                self.port_destination.clone() + &tab_word(self.port_destination.len(), MAX_PORT_LEN)
            ].join("\t")
        }
    }

    impl PacketExchange {
        pub fn new(protocols: Vec<String>, transmitted_bytes: usize, exchange_time: DateTime<Local>) -> Self {
            PacketExchange {
                protocols: HashSet::from_iter(protocols.into_iter()),
                first_exchange: exchange_time,
                last_exchange: exchange_time,
                transmitted_bytes,
            }
        }

        pub fn add_packet(&mut self, protocols: Vec<String>, transmitted_bytes: usize, exchange_time: DateTime<Local>) {
            for protocol in protocols {
                self.protocols.insert(protocol);
            }
            self.transmitted_bytes += transmitted_bytes;
            self.first_exchange = cmp::min(self.first_exchange, exchange_time);
            self.last_exchange = cmp::max(self.last_exchange, exchange_time);
        }
    }

    impl ToString for PacketExchange {
        fn to_string(&self) -> String {
            let first_exchange = self.first_exchange.format("%Y-%m-%d %H:%M:%S").to_string();
            let last_exchange = self.last_exchange.format("%Y-%m-%d %H:%M:%S").to_string();
            let first_exchange_len = first_exchange.len();
            let last_exchange_len = last_exchange.len();
            let bytes = human_bytes(self.transmitted_bytes as f64);
            let mut protocols_set = self.protocols.clone().into_iter().collect::<Vec<String>>();
            let protocols = if protocols_set.len() == 0 {
                "-".to_owned()
            } else {
                protocols_set.sort();
                "[".to_owned() + &protocols_set.join(", ") + "]"
            };

            [
                first_exchange + &tab_word(first_exchange_len, MAX_TIME_LEN),
                last_exchange + &tab_word(last_exchange_len, MAX_TIME_LEN),
                bytes.to_string() + &tab_word(bytes.to_string().len(), MAX_BYTES_LEN),
                protocols
            ].join("\t")
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{SourceDestination, PacketExchange};
        use std::collections::HashSet;
        use chrono::{Local, Duration};

        #[test]
        fn empty_packet_exchange() {
            let now = Local::now();
            let protocol = String::from("TCP");
            let protocols = HashSet::from([protocol.clone()]);
            let exchange = PacketExchange::new(vec!(protocol), 0, now);
            assert_eq!(exchange.protocols, protocols);
            assert_eq!(exchange.transmitted_bytes, 0);
            assert_eq!(exchange.first_exchange, now);
            assert_eq!(exchange.last_exchange, now);
        }

        #[test]
        fn full_packet_exchange() {
            let now = Local::now();
            let protocol = String::from("UDP");
            let protocols = HashSet::from([protocol.clone()]);
            let bytes = 100;
            let exchange = PacketExchange::new(vec!(protocol), bytes, now);
            assert_eq!(exchange.protocols, protocols);
            assert_eq!(exchange.transmitted_bytes, bytes);
            assert_eq!(exchange.first_exchange, now);
            assert_eq!(exchange.last_exchange, now);
        }

        #[test]
        fn add_packet_exchange_bytes() {
            let now = Local::now();
            let protocol = String::from("UDP");
            let bytes_1 = 100;
            let bytes_2 = 300;
            let mut exchange = PacketExchange::new(vec!(protocol.clone()), bytes_1, now);
            let protocols = HashSet::from([protocol.clone()]);
            exchange.add_packet(vec!(protocol), bytes_2, now);
            assert_eq!(exchange.protocols, protocols);
            assert_eq!(exchange.transmitted_bytes, bytes_1 + bytes_2);
            assert_eq!(exchange.first_exchange, now);
            assert_eq!(exchange.last_exchange, now);
        }

        #[test]
        fn add_packet_exchange_same_protocol() {
            let now = Local::now();
            let protocol = String::from("UDP");
            let bytes_1 = 100;
            let bytes_2 = 2100;
            let mut exchange = PacketExchange::new(vec!(protocol.clone()), bytes_1, now);
            let protocols = HashSet::from([protocol.clone()]);
            exchange.add_packet(vec!(protocol), bytes_2, now);
            assert_eq!(exchange.protocols, protocols);
            assert_eq!(exchange.transmitted_bytes, bytes_1 + bytes_2);
            assert_eq!(exchange.first_exchange, now);
            assert_eq!(exchange.last_exchange, now);
        }

        #[test]
        fn add_packet_exchange_multiple_protocols() {
            let now = Local::now();
            let protocol_1 = String::from("UDP");
            let protocol_2 = String::from("TCP");
            let bytes_1 = 100;
            let bytes_2 = 300;
            let protocols = HashSet::from([protocol_1.clone(), protocol_2.clone()]);
            let mut exchange = PacketExchange::new(vec!(protocol_1), bytes_1, now);
            exchange.add_packet(vec!(protocol_2), bytes_2, now);
            assert_eq!(exchange.protocols, protocols);
            assert_eq!(exchange.transmitted_bytes, bytes_1 + bytes_2);
            assert_eq!(exchange.first_exchange, now);
            assert_eq!(exchange.last_exchange, now);
        }

        #[test]
        fn add_packet_exchange_same_time() {
            let now = Local::now();
            let protocol_1 = String::from("UDP");
            let protocol_2 = String::from("TCP");
            let bytes_1 = 100;
            let bytes_2 = 300;
            let protocols = HashSet::from([protocol_1.clone(), protocol_2.clone()]);
            let mut exchange = PacketExchange::new(vec!(protocol_1), bytes_1, now);
            exchange.add_packet(vec!(protocol_2), bytes_2, now);
            assert_eq!(exchange.protocols, protocols);
            assert_eq!(exchange.transmitted_bytes, bytes_1 + bytes_2);
            assert_eq!(exchange.first_exchange, now);
            assert_eq!(exchange.last_exchange, now);
        }

        #[test]
        fn add_packet_exchange_before() {
            let now = Local::now();
            let future = Local::now() + Duration::seconds(5);
            let protocol_1 = String::from("UDP");
            let protocol_2 = String::from("TCP");
            let bytes_1 = 100;
            let bytes_2 = 300;
            let protocols = HashSet::from([protocol_1.clone(), protocol_2.clone()]);
            let mut exchange = PacketExchange::new(vec!(protocol_1), bytes_1, now);
            exchange.add_packet(vec!(protocol_2), bytes_2, future);
            assert_eq!(exchange.protocols, protocols);
            assert_eq!(exchange.transmitted_bytes, bytes_1 + bytes_2);
            assert_eq!(exchange.first_exchange, now);
            assert_eq!(exchange.last_exchange, future);
        }

        #[test]
        fn add_packet_exchange_after() {
            let now = Local::now();
            let past = Local::now() - Duration::seconds(5);
            let protocol_1 = String::from("UDP");
            let protocol_2 = String::from("TCP");
            let bytes_1 = 100;
            let bytes_2 = 300;
            let protocols = HashSet::from([protocol_1.clone(), protocol_2.clone()]);
            let mut exchange = PacketExchange::new(vec!(protocol_1), bytes_1, now);
            exchange.add_packet(vec!(protocol_2), bytes_2, past);
            assert_eq!(exchange.protocols, protocols);
            assert_eq!(exchange.transmitted_bytes, bytes_1 + bytes_2);
            assert_eq!(exchange.first_exchange, past);
            assert_eq!(exchange.last_exchange, now);
        }

        #[test]
        fn source_destination_ipv4() {
            let ip_source = String::from("1.1.1.1");
            let ip_destination = String::from("2.2.2.2");
            let port_source = String::from("23");
            let port_destination = String::from("40");
            let source_destination = SourceDestination::new(ip_source.clone(), ip_destination.clone(), port_source.clone(), port_destination.clone());
            assert_eq!(source_destination.ip_source, ip_source);
            assert_eq!(source_destination.ip_destination, ip_destination);
            assert_eq!(source_destination.port_source, port_source);
            assert_eq!(source_destination.port_destination, port_destination);
        }

        #[test]
        fn source_destination_ipv6() {
            let ip_source = String::from("ab:cd:00:11:2222:3:4:5");
            let ip_destination = String::from("a:b:c:d:e:f:0:1");
            let port_source = String::from("100");
            let port_destination = String::from("200");
            let source_destination = SourceDestination::new(ip_source.clone(), ip_destination.clone(), port_source.clone(), port_destination.clone());
            assert_eq!(source_destination.ip_source, ip_source);
            assert_eq!(source_destination.ip_destination, ip_destination);
            assert_eq!(source_destination.port_source, port_source);
            assert_eq!(source_destination.port_destination, port_destination);
        }
    }
}