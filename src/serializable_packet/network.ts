import {SerializablePacket} from "../types/sniffing";

export class ArpPacket implements SerializablePacket {
    hardware_type: string;
    protocol_type: number;
    hw_addr_len: number;
    proto_addr_len: number;
    operation: string;
    sender_hw_addr: string;
    sender_proto_addr: string;
    target_hw_addr: string;
    target_proto_addr: string;
    payload: [];

    constructor(
        hardware_type: string,
        protocol_type: number,
        hw_addr_len: number,
        proto_addr_len: number,
        operation: string,
        sender_hw_addr: string,
        sender_proto_addr: string,
        target_hw_addr: string,
        target_proto_addr: string,
        payload: []
    ) {
        this.hardware_type = hardware_type;
        this.protocol_type = protocol_type;
        this.hw_addr_len = hw_addr_len;
        this.proto_addr_len = proto_addr_len;
        this.operation = operation;
        this.sender_hw_addr = sender_hw_addr;
        this.sender_proto_addr = sender_proto_addr;
        this.target_hw_addr = target_hw_addr;
        this.target_proto_addr = target_proto_addr;
        this.payload = payload
    }
}