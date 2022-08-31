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

    public toDisplay() {
        let packet_info = [];

        packet_info.push( {"Destination MAC" : this.destination});
        packet_info.push( {"Source MAC" : this.destination});
        packet_info.push( {"Ethertype" : this.destination});

        return packet_info;
    }

    public getPayload(): number[] {
        return this.payload;
    }
}
