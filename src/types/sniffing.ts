export enum SniffingStatus {
    Inactive,
    Paused,
    Active
}

export interface SerializableTransportLayerPacket {
    toDisplay(): any;
    toString(): string;
}

export interface SerializableNetworkLayerPacket {
    toDisplay(): any;
    toString(): string;
}

export interface SerializableLinkLayerPacket {
    toDisplay(): any;
    toString(): string;
    getPayload(): number[];
    payloadToHex() : string[];
}

/* ParsedPacket */

export class Packet {
    id: number;
    // type: string;
    // length: number;
    link_layer_packet: SerializableLinkLayerPacket | null;
    network_layer_packet: SerializableNetworkLayerPacket | null;
    transport_layer_packet: SerializableTransportLayerPacket | null;

    constructor(
        id: number,
        link_layer_packet: SerializableLinkLayerPacket | null,
        network_layer_packet: SerializableNetworkLayerPacket | null,
        transport_layer_packet: SerializableTransportLayerPacket | null
    ) {
        this.id = id;
        // this.type =  //
        // this.length = //
        this.link_layer_packet = link_layer_packet;
        this.network_layer_packet = network_layer_packet;
        this.transport_layer_packet = transport_layer_packet;
    }

    // TODO: length and type
}