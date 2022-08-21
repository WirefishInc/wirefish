export enum TrafficType {
    Incoming,
    Outgoing
}

export enum SniffingStatus {
    Inactive,
    Paused,
    Active
}

export class Packet {
    id: number;
    sourceMAC: string;
    destinationMAC: string;
    ipVersion: string;
    sourceIP: string;
    destinationIP: string;
    protocol: string;
    trafficType: TrafficType;

    constructor(id: number, sourceMAC: string, destinationMAC: string, ipVersion: string, sourceIP: string, destinationIP: string, protocol: string, trafficType: TrafficType) {
        this.id = id;
        this.sourceMAC = sourceMAC;
        this.destinationMAC = destinationMAC;
        this.ipVersion = ipVersion;
        this.sourceIP = sourceIP;
        this.destinationIP = destinationIP;
        this.protocol = protocol;
        this.trafficType = trafficType;
    }
}