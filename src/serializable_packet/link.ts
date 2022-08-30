import {SerializablePacket} from "../types/sniffing"

export class EthernetPacket implements SerializablePacket {
    destination: string;
    source: string;
    ethertype: string;
    payload: [];

    constructor(destination: string, source: string, ethertype: string, payload: []) {
        this.destination = destination;
        this.source = source;
        this.ethertype = ethertype;
        this.payload = payload;
    }
}