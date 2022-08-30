import {SerializableLinkLayerPacket} from "../types/sniffing"

export class EthernetPacket implements SerializableLinkLayerPacket {
    destination: string;
    source: string;
    ethertype: string;
    payload: [];
    type: string;

    constructor(destination: string, source: string, ethertype: string, payload: []) {
        this.destination = destination;
        this.source = source;
        this.ethertype = ethertype;
        this.payload = payload;
        this.type = "Ethernet Packet"
    }
}