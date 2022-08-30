export enum SniffingStatus {
    Inactive,
    Paused,
    Active
}

export interface SerializableTransportLayerPacket {}
export interface SerializableNetworkLayerPacket {}
export interface SerializableLinkLayerPacket {}

/* ParsedPacket */

export class Packet {
    id:number;
   // type: string;
   // length: number;
    link_layer_packet: SerializableLinkLayerPacket;
    network_layer_packet: SerializableNetworkLayerPacket;
    transport_layer_packet: SerializableTransportLayerPacket;

    constructor(
        id: number,
        link_layer_packet: SerializableLinkLayerPacket,
        network_layer_packet: SerializableNetworkLayerPacket,
        transport_layer_packet: SerializableTransportLayerPacket
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