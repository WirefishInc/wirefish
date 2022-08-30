export enum TrafficType {
    Incoming,
    Outgoing
}

export enum SniffingStatus {
    Inactive,
    Paused,
    Active
}

export interface SerializablePacket {}

// ParsedPacket
export class Packet {
    link_layer_packet: SerializablePacket;
    network_layer_packet: SerializablePacket;
    transport_layer_packet: SerializablePacket;


    constructor(link_layer_packet: SerializablePacket, network_layer_packet: SerializablePacket, transport_layer_packet: SerializablePacket ) {
        this.link_layer_packet = link_layer_packet;
        this.network_layer_packet = network_layer_packet;
        this.transport_layer_packet = transport_layer_packet;
    }
/*
    id: number;
    type: string;
    sourceMAC: string;
    destinationMAC: string;
    sourceIP: string;
    destinationIP: string;
    length: number;
    info: string;
    trafficType: TrafficType;

    constructor(id: number, type: string, sourceMAC: string, destinationMAC: string, sourceIP: string, destinationIP: string, length: number, info: string, trafficType: TrafficType) {
        this.id = id;
        this.type = type;
        this.sourceMAC = sourceMAC;
        this.destinationMAC = destinationMAC;
        this.sourceIP = sourceIP;
        this.destinationIP = destinationIP;
        this.length = length;
        this.info = info;
        this.trafficType = trafficType;
    }
 */
}