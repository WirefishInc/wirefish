import {SerializableApplicationLayerPacket} from "../types/sniffing";
import {
    ChangeCipherSpecMessage,
    CustomAlertMessage,
    CustomApplicationDataMessage,
    CustomEncryptedMessage,
    CustomHandshakeMessage,
    CustomHeartbeatMessage,
    CustomTlsMessages
} from "./tls";

export class TlsPacket implements SerializableApplicationLayerPacket {
    version: string;
    messages: CustomTlsMessages[];
    length: number;
    type: string

    constructor(version: string, messages: any[], length: number) {
        this.version = version;
        this.messages = this.setMessages(messages);
        this.length = length;
        this.type = "Transport Layer Security"
    }

    private setMessages(messages: any[]): CustomTlsMessages[] {
        let result: CustomTlsMessages[] = [];

        messages.forEach((message) => {
            switch (message.type) {
                case "Handshake":
                    // todo
                    break;
                case "Alert":
                    result.push(new CustomAlertMessage(message.severity, message.description))
                    break;
                case "ApplicationData":
                    result.push(new CustomApplicationDataMessage(message.data))
                    break;
                case "Heartbeat":
                    result.push(new CustomHeartbeatMessage(message.heartbeat_type, message.payload, message.payload_len))
                    break;
                case "Encrypted":
                    result.push(new CustomEncryptedMessage(message.data))
                    break;
                case "ChangeCipherSpec":
                    result.push(new ChangeCipherSpecMessage())
                    break;
            }

        })

        return result;
    }

    // todo
    // @ts-ignore ! remove it
    private make_sub_type_packet() : CustomHandshakeMessage {
    }

    getInfo(): string {
        let res = "";

        this.messages.forEach( (message) => {
            res += message.getType()+", ";
        })

        return res.slice(0,-2);
    }

    getType(): string {
        return this.version;
    }

    // todo: get all messagges
    toDisplay() {
        return []
    }

    toString(): string {
        return this.type
    }
}

export class HttpResponsePacket implements SerializableApplicationLayerPacket {
    version: number;
    code: number;
    reason: string;
    headers: [[string, string]];
    payload: number[];
    type: string;

    constructor(
        version: number,
        code: number,
        reason: string,
        headers: [[string, string]],
        payload: number[]
    ) {
        this.version = version;
        this.code = code;
        this.reason = reason;
        this.headers = headers;
        this.payload = payload;
        this.type = "Hypertext Transfer Protocol"
    }

    getInfo(): string {
        return "Response";
    }

    getType(): string {
        return "HTTP";
    }

    toDisplay() {
        let packet_info = [];

        packet_info.push({"Response Version": this.version});
        packet_info.push({"Status Code": this.code});
        packet_info.push({"Reason": this.reason});

        this.headers.forEach((h) => {
            let key: string = h[0];
            let obj = {};

            // @ts-ignore
            obj[key] = h[1];

            packet_info.push(obj);
        })

        return packet_info;
    }

    toString(): string {
        return this.type;
    }

}


export class HttpRequestPacket implements SerializableApplicationLayerPacket {
    method: string;
    path: string;
    version: number;
    headers: [[string, string]];
    payload: number[];
    type: string;

    constructor(
        method: string,
        path: string,
        version: number,
        headers: [[string, string]],
        payload: number[]
    ) {
        this.method = method;
        this.path = path;
        this.version = version;
        this.headers = headers;
        this.payload = payload;
        this.type = "Hypertext Transfer Protocol"
    }

    getInfo(): string {
        return this.method + " " + this.path;
    }

    getType(): string {
        return "HTTP";
    }

    toDisplay(): any {
        let packet_info = [];

        packet_info.push({"Request Method": this.method});
        packet_info.push({"Request URI": this.path});
        packet_info.push({"Request Version": this.version});

        this.headers.forEach((h) => {
            let key: string = h[0];
            let obj = {};

            // @ts-ignore
            obj[key] = h[1];

            packet_info.push(obj);
        })

        return packet_info;
    }

    toString(): string {
        return this.type;
    }

}