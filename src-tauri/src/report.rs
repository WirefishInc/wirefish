//! This crate allows the generation of a periodic report in .csv format
//! The report highlights the the first and last timestamp, the amount of traffic,
//! and the protocols of data exchange for all connections identified
//! by (Source IP, Destination IP, Source Port, Destination Port)
//!
//! The following example describes how to use the defined data structures and generate a report:
//!
//! ```
//! use report::{
//!    data::{PacketExchange, SourceDestination},
//!    write_report
//! };
//! use chrono::Local;
//!
//! fn main() {
//!
//!     // Create a hashmap to hold all packet exchanges
//!     let exchanged_packets = HashMap::<SourceDestination, PacketExchange>::new();
//!
//!     // Create Sender-Receiver pair
//!     let source_destination = SourceDestination::new(
//!         network_source,
//!         network_destination,
//!         transport_source,
//!         transport_destination
//!     );
//!
//!     // Insert a packet in the hashmap
//!     let now = Local::now();
//!     let transmitted_bytes = 1024;
//!     let mut protocol = vec![String::from("IPv4"), String::from("UDP")];
//!     exchanged_packets
//!         .entry(source_destination)
//!         .and_modify(|exchange| {
//!             // Update data about exchanged packets
//!             exchange.add_packet(protocols.clone(), transmitted_bytes, now)
//!         })
//!         // Create a new Packet Exchange if none was found
//!         .or_insert(PacketExchange::new(protocols, transmitted_bytes, now));
//!
//!     // Generate report
//!     let report_path = "./path/to/report.csv";
//!     let mut first_generation = true; // Only the first time, this adds the csv header
//!     write_report(report_path, exchanged_packets, first_generation);
//!
//!     // From the second time onwards
//!     first_generation = false;
//!
//!     // .. Add packets exchange ..
//!     write_report(report_path, exchanged_packets, first_generation);
//!
//!     // .. Add packets exchange ..
//!     write_report(report_path, exchanged_packets, first_generation);
//! }
//! ```

use self::data::{SourceDestination, PacketExchange};
use std::io::{self, Write, BufWriter};
use std::fs::{self, OpenOptions};
use std::collections::HashMap;
use std::path::Path;
use std::ffi::OsStr;

/// Appends data to a report file, creates the file if it doesn't exist
///
/// The file and the directory path to it are created if they do not exist.
/// The hashmap is consumed and its content is written in the csv file indicated by the path.
/// If the first_generation attribute it's true any file corresponding to the provided path will
/// be deleted and a new file will be generated with a header containing the name of the fields.pub fn write_report(output_path: &str, data: &mut HashMap<SourceDestination, PacketExchange>, first_generation: bool) -> Result<bool, io::Error> {
    let path = Path::new(&output_path);
    let mut file_exists = path.is_file();
    let file_extension = path.extension();

    // Check file extension is .csv
    if file_extension.is_none() || file_extension.and_then(OsStr::to_str).unwrap() != "csv" {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "Provide a .csv file"));
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

    // Write report headers
    if first_generation {
        let headers = [
            "Source IP",
            "Destination IP",
            "Source Port",
            "Destination Port",
            "First Data Exchange",
            "Last Data Exchange",
            "Bytes Exchanged",
            "Protocols"
        ];
        writer.write_all((headers.join(",") + "\n").as_bytes())?;
    }

    let mut data_pairs = data.drain().peekable();

    if data_pairs.peek().is_some() {
        // Write packets exchange data
        for (source_destination, exchange) in data_pairs {
            writer.write_all((source_destination.to_string() + "," + &exchange.to_string() + "\n").as_bytes())?
        }
        writer.write_all(b"\n")?;
    }

    Ok(true)
}

/// Returns (Source IP, Destination IP, Source Port, Destination Port, and Protocols) contained in a packet



/// Data structures used to write a report
pub mod data {
    use std::collections::HashSet;
    use chrono::{DateTime, Local};
    use std::cmp;

    /// Ip addresses and port numbers of source and destination of a packet exchange
    #[derive(PartialEq, Eq, Hash, Debug)]
    pub struct SourceDestination {
        pub ip_source: String,
        pub ip_destination: String,
        pub port_source: String,
        pub port_destination: String,
    }

    /// Data structure describing the list of protocols, total bytes, and timestamps of the
    /// first and last packet exchange in a connection
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
                self.ip_source.clone(),
                self.ip_destination.clone(),
                self.port_source.clone(),
                self.port_destination.clone()
            ].join(",")
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

        /// Merge two packet exchanges together: unite the protocol vectors, sum the transmitted
        /// bytes and set the first_exchange to the oldest timestamp and set last_exchange to the
        /// newest timestamp
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
            let mut protocols_set = self.protocols.clone().into_iter().collect::<Vec<String>>();
            let protocols = if protocols_set.len() == 0 {
                "-".to_owned()
            } else {
                protocols_set.sort();
                protocols_set.join(";")
            };

            [
                first_exchange,
                last_exchange,
                self.transmitted_bytes.to_string(),
                protocols
            ].join(",")
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