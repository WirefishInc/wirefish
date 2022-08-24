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
}