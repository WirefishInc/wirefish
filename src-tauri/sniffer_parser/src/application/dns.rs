//! DNS Packet parsing

use dns_parser::Packet as DnsPacket;
use log::debug;
use std::net::IpAddr;

use crate::serializable_packet::{
    application::SerializableDnsPacket, ParsedPacket, SerializablePacket,
};

/// Build a DNS packet from a transport-layer packet, save it in a Parsed Packet
pub fn handle_dns_packet(
    source_ip: IpAddr,
    source_port: u16,
    dest_ip: IpAddr,
    dest_port: u16,
    packet: &[u8],
    parsed_packet: &mut ParsedPacket,
) {
    if let Ok(dns_packet) = DnsPacket::parse(packet) {
        debug!(
            "DNS Packet: {}:{} > {}:{}; ID: {}, Questions: {}, Answers: {}, Authority: {}, Additional: {}",
            source_ip,
            source_port,
            dest_ip,
            dest_port,
            dns_packet.header.id,
            dns_packet.header.questions,
            dns_packet.header.answers,
            dns_packet.header.nameservers,
            dns_packet.header.additional,
        );

        parsed_packet.set_application_layer_packet(Some(SerializablePacket::DnsPacket(
            SerializableDnsPacket::from(&dns_packet),
        )));
    } else {
        debug!("Malformed DNS Packet");
        parsed_packet.set_application_layer_packet(Some(SerializablePacket::MalformedPacket(
            "Malformed DNS Packet".to_string(),
        )));
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use dns_parser::{Packet as ParseDnsPacket, RData as ParseRData};
    use simple_dns::{
        rdata::{RData as NewRData, A as NewA},
        Name, Packet as NewDnsPacket, Question, ResourceRecord, CLASS, TYPE,
    };

    use crate::serializable_packet::{
        application::CustomResourceData, ParsedPacket, SerializablePacket,
    };

    use super::handle_dns_packet;
    const ID: u16 = 0x1234;

    #[test]
    fn empty_dns_query() {
        let dns_packet = NewDnsPacket::new_query(ID, false);
        let mut parsed_packet = ParsedPacket::new(0);

        handle_dns_packet(
            IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10)),
            4444,
            IpAddr::V4(Ipv4Addr::new(11, 11, 11, 11)),
            53,
            dns_packet.build_bytes_vec().unwrap().as_slice(),
            &mut parsed_packet,
        );

        match parsed_packet.get_application_layer_packet().unwrap() {
            SerializablePacket::DnsPacket(new_dns_packet) => {
                assert_eq!(new_dns_packet.header.id, dns_packet.header.id);
                assert_eq!(new_dns_packet.header.query, dns_packet.header.query);
                assert_eq!(
                    new_dns_packet.header.opcode,
                    format!("{:?}", dns_packet.header.opcode)
                );
                assert_eq!(
                    new_dns_packet.header.authoritative,
                    dns_packet.header.authoritative_answer
                );
                assert_eq!(new_dns_packet.header.truncated, dns_packet.header.truncated);
                assert_eq!(
                    new_dns_packet.header.recursion_desired,
                    dns_packet.header.recursion_desired
                );
                assert_eq!(
                    new_dns_packet.header.recursion_available,
                    dns_packet.header.recursion_available
                );
                assert_eq!(
                    new_dns_packet.header.authenticated_data,
                    dns_packet.header.authentic_data
                );
                assert_eq!(
                    new_dns_packet.header.checking_disabled,
                    dns_packet.header.checking_disabled
                );
                assert_eq!(
                    new_dns_packet.header.response_code,
                    format!("{:?}", dns_packet.header.response_code)
                );
                assert_eq!(
                    new_dns_packet.header.num_questions,
                    dns_packet.header.questions_count
                );
                assert_eq!(
                    new_dns_packet.header.num_answers,
                    dns_packet.header.answers_count
                );
                assert_eq!(
                    new_dns_packet.header.num_nameservers,
                    dns_packet.header.name_servers_count
                );
                assert_eq!(
                    new_dns_packet.header.num_additional,
                    dns_packet.header.additional_records_count
                );

                assert_eq!(
                    new_dns_packet.additional.len(),
                    dns_packet.additional_records.len()
                );
                assert_eq!(new_dns_packet.answers.len(), dns_packet.answers.len());
                assert_eq!(
                    new_dns_packet.nameservers.len(),
                    dns_packet.name_servers.len()
                );
                assert_eq!(new_dns_packet.questions.len(), dns_packet.questions.len());
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn dns_query_with_some_questions() {
        let mut dns_packet = NewDnsPacket::new_query(ID, false);
        let question = Question::new(
            Name::new_unchecked("_srv._udp.local"),
            TYPE::TXT.into(),
            CLASS::IN.into(),
            false,
        );

        dns_packet.questions.push(question);
        dns_packet.header.questions_count = 1;

        let dns_packet_bytes = dns_packet.build_bytes_vec().unwrap();
        let mut parsed_packet = ParsedPacket::new(0);
        handle_dns_packet(
            IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10)),
            4444,
            IpAddr::V4(Ipv4Addr::new(11, 11, 11, 11)),
            53,
            dns_packet_bytes.as_slice(),
            &mut parsed_packet,
        );

        match parsed_packet.get_application_layer_packet().unwrap() {
            SerializablePacket::DnsPacket(new_dns_packet) => {
                let dns_packet = ParseDnsPacket::parse(dns_packet_bytes.as_slice()).unwrap();
                assert_eq!(new_dns_packet.questions.len(), dns_packet.questions.len());

                let new_question = &new_dns_packet.questions[0];
                assert_eq!(
                    new_question.query_name,
                    dns_packet.questions[0].qname.to_string()
                );
                assert_eq!(
                    new_question.prefer_unicast,
                    dns_packet.questions[0].prefer_unicast
                );
                assert_eq!(
                    new_question.query_type,
                    format!("{:?}", dns_packet.questions[0].qtype)
                );
                assert_eq!(
                    new_question.query_class,
                    format!("{:?}", dns_packet.questions[0].qclass)
                );
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn dns_reply_with_some_answers() {
        let mut dns_packet = NewDnsPacket::new_reply(ID);
        let resource = ResourceRecord::new(
            Name::new_unchecked("_srv._udp.local"),
            CLASS::IN,
            10,
            NewRData::A(NewA { address: 10 }),
        );

        dns_packet.answers.push(resource);
        dns_packet.header.answers_count = 1;

        let dns_packet_bytes = dns_packet.build_bytes_vec().unwrap();
        let mut parsed_packet = ParsedPacket::new(0);
        handle_dns_packet(
            IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10)),
            4444,
            IpAddr::V4(Ipv4Addr::new(11, 11, 11, 11)),
            53,
            dns_packet_bytes.as_slice(),
            &mut parsed_packet,
        );

        match parsed_packet.get_application_layer_packet().unwrap() {
            SerializablePacket::DnsPacket(new_dns_packet) => {
                let dns_packet = ParseDnsPacket::parse(dns_packet_bytes.as_slice()).unwrap();
                assert_eq!(new_dns_packet.answers.len(), dns_packet.answers.len());

                let new_answer = &new_dns_packet.answers[0];
                assert_eq!(new_answer.name, dns_packet.answers[0].name.to_string());
                assert_eq!(
                    new_answer.multicast_unique,
                    dns_packet.answers[0].multicast_unique
                );
                assert_eq!(new_answer.class, format!("{:?}", dns_packet.answers[0].cls));
                assert_eq!(new_answer.ttl, dns_packet.answers[0].ttl);

                let new_answer_data = &new_dns_packet.answers[0].data;

                match (new_answer_data, &dns_packet.answers[0].data) {
                    (CustomResourceData::A(new_data), ParseRData::A(data)) => {
                        assert_eq!(new_data.address, Ipv4Addr::from(data.0));
                    }
                    _ => unreachable!(),
                }
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn dns_reply_with_some_additional() {
        let mut dns_packet = NewDnsPacket::new_reply(ID);
        let resource = ResourceRecord::new(
            Name::new_unchecked("_srv._udp.local"),
            CLASS::IN,
            10,
            NewRData::A(NewA { address: 10 }),
        );

        dns_packet.additional_records.push(resource);
        dns_packet.header.additional_records_count = 1;

        let dns_packet_bytes = dns_packet.build_bytes_vec().unwrap();
        let mut parsed_packet = ParsedPacket::new(0);
        handle_dns_packet(
            IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10)),
            4444,
            IpAddr::V4(Ipv4Addr::new(11, 11, 11, 11)),
            53,
            dns_packet_bytes.as_slice(),
            &mut parsed_packet,
        );

        match parsed_packet.get_application_layer_packet().unwrap() {
            SerializablePacket::DnsPacket(new_dns_packet) => {
                let dns_packet = ParseDnsPacket::parse(dns_packet_bytes.as_slice()).unwrap();
                assert_eq!(new_dns_packet.additional.len(), dns_packet.additional.len());

                let new_additional = &new_dns_packet.additional[0];
                assert_eq!(
                    new_additional.name,
                    dns_packet.additional[0].name.to_string()
                );
                assert_eq!(
                    new_additional.multicast_unique,
                    dns_packet.additional[0].multicast_unique
                );
                assert_eq!(
                    new_additional.class,
                    format!("{:?}", dns_packet.additional[0].cls)
                );
                assert_eq!(new_additional.ttl, dns_packet.additional[0].ttl);

                let new_additional_data = &new_dns_packet.additional[0].data;

                match (new_additional_data, &dns_packet.additional[0].data) {
                    (CustomResourceData::A(new_data), ParseRData::A(data)) => {
                        assert_eq!(new_data.address, Ipv4Addr::from(data.0));
                    }
                    _ => unreachable!(),
                }
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn dns_reply_with_some_nameserver() {
        let mut dns_packet = NewDnsPacket::new_reply(ID);
        let resource = ResourceRecord::new(
            Name::new_unchecked("_srv._udp.local"),
            CLASS::IN,
            10,
            NewRData::A(NewA { address: 10 }),
        );

        dns_packet.name_servers.push(resource);
        dns_packet.header.name_servers_count = 1;

        let dns_packet_bytes = dns_packet.build_bytes_vec().unwrap();
        let mut parsed_packet = ParsedPacket::new(0);
        handle_dns_packet(
            IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10)),
            4444,
            IpAddr::V4(Ipv4Addr::new(11, 11, 11, 11)),
            53,
            dns_packet_bytes.as_slice(),
            &mut parsed_packet,
        );

        match parsed_packet.get_application_layer_packet().unwrap() {
            SerializablePacket::DnsPacket(new_dns_packet) => {
                let dns_packet = ParseDnsPacket::parse(dns_packet_bytes.as_slice()).unwrap();
                assert_eq!(
                    new_dns_packet.nameservers.len(),
                    dns_packet.nameservers.len()
                );

                let new_nameserver = &new_dns_packet.nameservers[0];
                assert_eq!(
                    new_nameserver.name,
                    dns_packet.nameservers[0].name.to_string()
                );
                assert_eq!(
                    new_nameserver.multicast_unique,
                    dns_packet.nameservers[0].multicast_unique
                );
                assert_eq!(
                    new_nameserver.class,
                    format!("{:?}", dns_packet.nameservers[0].cls)
                );
                assert_eq!(new_nameserver.ttl, dns_packet.nameservers[0].ttl);

                let new_nameservers_data = &new_dns_packet.nameservers[0].data;

                match (new_nameservers_data, &dns_packet.nameservers[0].data) {
                    (CustomResourceData::A(new_data), ParseRData::A(data)) => {
                        assert_eq!(new_data.address, Ipv4Addr::from(data.0));
                    }
                    _ => unreachable!(),
                }
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn malformed_dns_packet() {
        let malformed_dns_packet = [0, 1, 2, 3, 0, 1, 2, 3];
        let mut parsed_packet = ParsedPacket::new(0);
        handle_dns_packet(
            IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10)),
            4444,
            IpAddr::V4(Ipv4Addr::new(11, 11, 11, 11)),
            53,
            malformed_dns_packet.as_slice(),
            &mut parsed_packet,
        );

        match parsed_packet.get_application_layer_packet().unwrap() {
            SerializablePacket::MalformedPacket(str) => assert_eq!(str, "Malformed DNS Packet"),
            _ => unreachable!(),
        };
    }
}
