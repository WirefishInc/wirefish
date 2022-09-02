import {SerializableLinkLayerPacket} from "../types/sniffing"

export class EthernetPacket implements SerializableLinkLayerPacket {
    destination: string;
    source: string;
    ethertype: string;
    payload: number[];
    type: string;

    constructor(destination: string, source: string, ethertype: string, payload: number[]) {
        this.destination = destination;
        this.source = source;
        this.ethertype = ethertype;
        this.payload = payload;
        this.type = "Ethernet"
    }

    public toDisplay() {
        let packet_info = [];

        packet_info.push( {"Destination MAC" : this.destination});
        packet_info.push( {"Source MAC" : this.source});
        packet_info.push( {"Ethertype" : this.ethertype});

        return packet_info;
    }

    public toString() : string {
        return this.type+", src: "+this.source+", dst: "+this.destination
    }

    public getPayload() : number[] {
        return this.payload;
    }

    public payloadToHex() : string[] {
       return this.payload.reverse().map( (el:number) => el.toString(16)); // dec to hex
    }
}
