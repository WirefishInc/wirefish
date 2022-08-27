pub mod report {
    use crate::{SourceDestination, PacketExchange};
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
        writer.write_all(("-".repeat(50) + "\n\n").as_bytes())?;
        writer.write_all((">> Updated at: ".to_owned() + &Local::now().format("%Y-%m-%d %H:%M:%S").to_string() + "\n").as_bytes())?;
        writer.write_all((">> Collected entries: ".to_owned() + &data.len().to_string() + "\n\n").as_bytes())?;
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
            transmitted_bytes: usize,
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
                    transmitted_bytes,
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
    }
}