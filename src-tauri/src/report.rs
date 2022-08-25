use self::data::{SourceDestination, PacketExchange};
use std::io::{self, Write, BufWriter};
use std::fs::{self, OpenOptions};
use std::collections::HashMap;
use std::path::Path;
use std::ffi::OsStr;
use chrono::Local;

/// Appends data to a report file, creates the file if it doesn't exist
pub fn write_report(output_path: &str, data: &mut HashMap<SourceDestination, PacketExchange>) -> Result<(), io::Error> {
    let path = Path::new(output_path);
    let file_exists = path.is_file();
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
    }

    // Open file in append mode, create it if it doesn't exist
    let file = OpenOptions::new()
        .append(true)
        .create(!file_exists)
        .open(path)?;
    let mut writer = BufWriter::new(file);

    // Write report metadata
    let transmitted_bytes = data.values().map(|exchange| exchange.transmitted_bytes).reduce(|accum, item| accum + item).unwrap();
    writer.write_all(("-".repeat(50) + "\n\n").as_bytes())?;
    writer.write_all((">> Updated at: ".to_owned() + &Local::now().format("%Y-%m-%d %H:%M:%S").to_string() + "\n").as_bytes())?;
    writer.write_all((">> Collected entries: ".to_owned() + &data.len().to_string() + "\n").as_bytes())?;
    writer.write_all((">> Total Bytes transmitted: ".to_owned() + &transmitted_bytes.to_string() + "\n\n").as_bytes())?;
    writer.write_all("Source Ip \t\t\t\t\t\t\t\t    Destination Ip  \t\t\t\t\t\t    Source Port Destination Port		Data Exchanged	First Data Exchange\t\tLast Data Exchange".as_bytes())?;

    // Write packets exchange data
    for (source_destination, exchange) in data.drain() {
        writer.write_all((source_destination.to_string() + "\t\t" + &exchange.to_string() + "\n").as_bytes())?
    }
    writer.write_all(b"\n")?;

    Ok(())
}

pub mod data {
    use std::collections::HashSet;
    use chrono::{DateTime, Local};
    use std::cmp;

    #[derive(PartialEq, Eq, Hash)]
    pub struct SourceDestination {
        ip_source: String,
        ip_destination: String,
        port_source: String,
        port_destination: String,
    }

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
            const MAX_IP_LEN: usize = 39;
            let extra_tabs = |text_len: usize| { "\t".repeat((MAX_IP_LEN - text_len) / 4) };

            [
                self.ip_source.clone() + &extra_tabs(self.ip_source.len()),
                self.ip_destination.clone() + &extra_tabs(self.ip_destination.len()),
                self.port_source.clone(),
                self.port_destination.clone()
            ].join("\t\t")
        }
    }

    impl PacketExchange {
        pub fn new(protocol: String, transmitted_bytes: usize, exchange_time: DateTime<Local>) -> Self {
            PacketExchange {
                protocols: HashSet::from([protocol]),
                transmitted_bytes: transmitted_bytes,
                first_exchange: exchange_time,
                last_exchange: exchange_time,
            }
        }

        pub fn add_packet(&mut self, protocol: String, transmitted_bytes: usize, exchange_time: DateTime<Local>) {
            self.protocols.insert(protocol);
            self.transmitted_bytes += transmitted_bytes;
            self.first_exchange = cmp::min(self.first_exchange, exchange_time);
            self.last_exchange = cmp::max(self.last_exchange, exchange_time);
        }
    }

    impl ToString for PacketExchange {
        fn to_string(&self) -> String {
            [
                "[".to_owned() + &self.protocols.clone().into_iter().collect::<Vec<String>>().join(", ") + "]",
                self.transmitted_bytes.to_string() + " Bytes",
                self.first_exchange.format("%Y-%m-%d %H:%M:%S").to_string(),
                self.last_exchange.format("%Y-%m-%d %H:%M:%S").to_string()
            ].join("\t\t")
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
            let exchange = PacketExchange::new(protocol, 0, now);
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
            let exchange = PacketExchange::new(protocol, bytes, now);
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
            let mut exchange = PacketExchange::new(protocol.clone(), bytes_1, now);
            let protocols = HashSet::from([protocol.clone()]);
            exchange.add_packet(protocol, bytes_2, now);
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
            let mut exchange = PacketExchange::new(protocol.clone(), bytes_1, now);
            let protocols = HashSet::from([protocol.clone()]);
            exchange.add_packet(protocol, bytes_2, now);
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
            let mut exchange = PacketExchange::new(protocol_1, bytes_1, now);
            exchange.add_packet(protocol_2, bytes_2, now);
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
            let mut exchange = PacketExchange::new(protocol_1, bytes_1, now);
            exchange.add_packet(protocol_2, bytes_2, now);
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
            let mut exchange = PacketExchange::new(protocol_1, bytes_1, now);
            exchange.add_packet(protocol_2, bytes_2, future);
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
            let mut exchange = PacketExchange::new(protocol_1, bytes_1, now);
            exchange.add_packet(protocol_2, bytes_2, past);
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