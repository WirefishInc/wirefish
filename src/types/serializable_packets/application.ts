import {MalformedPacket, SerializableApplicationLayerPacket, UnknownPacket} from "../sniffing";
import {
    CertificateMessage,
    CertificateRequestMessage, CertificateStatusMessage,
    CertificateVerifyMessage,
    ChangeCipherSpecMessage,
    ClientHelloMessage,
    ClientKeyExchangeMessage,
    CustomAlertMessage,
    CustomApplicationDataMessage,
    CustomEncryptedMessage,
    CustomHandshakeMessage,
    CustomHeartbeatMessage, CustomMalformedMessage,
    CustomTlsMessages,
    EndOfEarlyData,
    FinishedMessage,
    HelloRequest,
    HelloRetryRequestMessage,
    KeyUpdate, NewSessionTicketMessage, NextProtocolMessage, ServerDoneMessage,
    ServerHelloMessage, ServerHelloV13Draft18Message, ServerKeyExchangeMessage
} from "./tls";
import {DnsHeader, DnsQuestion, DnsResourceRecord} from "./dns";
import {Buffer} from "buffer";

export class TlsPacket implements SerializableApplicationLayerPacket {
    version: string;
    messages: CustomTlsMessages[];
    length: number;
    type: string

    constructor(version: string, messages: any[], length: number) {
        this.version = version;
        this.messages = this.setMessages(messages);
        this.length = length;
        this.type = "TLS"
    }

    private setMessages(messages: any[]): CustomTlsMessages[] {
        let result: CustomTlsMessages[] = [];

        messages.forEach((message) => {
            switch (message.type) {
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
                    result.push(new CustomEncryptedMessage(message.data, message.version, message.message_type))
                    break;
                case "ChangeCipherSpec":
                    result.push(new ChangeCipherSpecMessage())
                    break;
                case "Handshake":
                    let packet = TlsPacket.set_subtype_packet(message);
                    if (packet)
                        result.push(packet)
                    break;
                case "Malformed":
                    result.push(new CustomMalformedMessage(
                        message.version,
                        message.message_type,
                        message.error_type,
                        message.data
                    ))
                    break;
                default:
                    result.push(new UnknownPacket())
            }
        })

        return result;
    }

    private static set_subtype_packet(message: any): CustomHandshakeMessage | null {
        let result: CustomHandshakeMessage | null = null;
        let p = message.content;

        switch (message.subType) {
            case "ClientHello":
                result = new ClientHelloMessage(
                    p.version,
                    p.rand_time,
                    p.rand_data,
                    p.session_id,
                    p.ciphers,
                    p.compressions,
                    p.extensions
                )
                break;
            case "ServerHello":
                result = new ServerHelloMessage(
                    p.version,
                    p.rand_time,
                    p.rand_data,
                    p.session_id,
                    p.cipher,
                    p.compression,
                    p.extensions
                )
                break;
            case "Certificate":
                result = new CertificateMessage(p.certificates);
                break;
            case "CertificateRequest":
                result = new CertificateRequestMessage(p.sig_hash_algos)
                break;
            case "CertificateStatus":
                result = new CertificateStatusMessage(
                    p.status_type,
                    p.data
                )
                break;
            case "CertificateVerify":
                result = new CertificateVerifyMessage(p.data)
                break;
            case "EndOfEarlyData":
                result = new EndOfEarlyData();
                break;
            case "Finished":
                result = new FinishedMessage(p.data);
                break;
            case "HelloRequest":
                result = new HelloRequest();
                break;
            case "HelloRetryRequest":
                result = new HelloRetryRequestMessage(
                    p.cipher,
                    p.extensions,
                    p.version
                )
                break;
            case "KeyUpdate":
                result = new KeyUpdate(p.key)
                break;
            case "NewSessionTicket":
                result = new NewSessionTicketMessage(
                    p.ticket,
                    p.ticket_lifetime_hint
                )
                break;
            case "NextProtocol":
                result = new NextProtocolMessage(
                    p.selected_protocol,
                    p.padding
                )
                break;
            case "ServerDone":
                result = new ServerDoneMessage(p.data)
                break;
            case "ServerHelloV13Draft18":
                new ServerHelloV13Draft18Message(
                    p.version,
                    p.random,
                    p.cipher,
                    p.extensions
                )
                break;
            case "ClientKeyExchange":
                result = new ClientKeyExchangeMessage(p.parameters)
                break;
            case "ServerKeyExchange":
                result = new ServerKeyExchangeMessage(p.parameters)
                break;
            default:
                result = new MalformedPacket();
        }

        return result;
    }

    getInfo(): string {
        let res = "";

        this.messages.forEach((message) => {
            res += message.getType() + ", ";
        })

        return res.slice(0, -2);
    }

    getType(): string {
        return this.type;
    }

    toDisplay(): any[] {
        let result: any[] = [];

        this.messages.forEach((m) => result.push({"name": m.toString(), "fields": m.toDisplay()}))

        return result;
    }

    toString(): string {
        return this.version + " Transport Layer Security"
    }
}

class HttpContentType {
    static setPayloadType(payload: any): any {
        let result: any = {};

        switch (payload.type) {
            case "TextCorrectlyDecoded":
                result.payload = payload.content;
                result.payload_type = "Text Correctly Decoded"
                break;
            case "TextMalformedDecoded":
                result.payload = payload.content;
                result.payload_type = "Text Malformed Decoded"
                break;
            case "TextDefaultDecoded":
                result.payload = payload.content;
                result.payload_type = "Text Default Decoded"
                break;
            case "Image":
                result.payload = payload.content;
                result.payload_type = "Image"
                break;
            case "Unknown":
                result.payload = payload.content;
                result.payload_type = "Unknown"
                break;
            case "Encoded":
                result.payload = payload.content;
                result.payload_type = "Encoded"
                break;
            case "Multipart":
                result.payload = payload.content;
                result.payload_type = "Multipart"
                break;
            default:
                result.payload = [];
                result.payload_type = ""
        }

        return result;
    }
}

export class HttpResponsePacket implements SerializableApplicationLayerPacket {
    version: number;
    code: number;
    reason: string;
    headers: [[string, string]];
    payload: number[] | string;
    payload_type: string;
    src: string;
    type: string;

    constructor(
        version: number,
        code: number,
        reason: string,
        headers: [[string, string]],
        payload: any
    ) {
        this.version = version;
        this.code = code;
        this.reason = reason;
        this.headers = headers;

        let res = HttpContentType.setPayloadType(payload);
        this.payload_type = res.payload_type;
        this.payload = res.payload;
        if (res.payload_type === "Image")
            this.src = "data:image/png;base64," + Buffer.from(this.payload).toString('base64')
        else
            this.src = "";

        this.type = "Hypertext Transfer Protocol"
    }

    getInfo(): string {
        return "HTTP Response";
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

        if (this.payload.length > 0)
            if (Array.isArray(this.payload))
                packet_info.push({
                    "HTTPResp": {
                        "type": this.payload_type,
                        "content": this.payload.toString(),
                        "src": this.src
                    }
                })
            else
                packet_info.push({"HTTPResp": {"type": this.payload_type, "content": this.payload, "src": this.src}})

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
    payload: number[] | string;
    payload_type: string;
    type: string;

    constructor(
        method: string,
        path: string,
        version: number,
        headers: [[string, string]],
        payload: any
    ) {
        this.method = method;
        this.path = path;
        this.version = version;
        this.headers = headers;

        let res = HttpContentType.setPayloadType(payload);
        this.payload_type = res.payload_type;
        this.payload = res.payload;

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

        if (this.payload.length > 0) {
            if (Array.isArray(this.payload))
                packet_info.push({"HTTPResp": {"type": this.payload_type, "content": this.payload.toString()}})
            else
                packet_info.push({"HTTPReq": {"type": this.payload_type, "content": this.payload}})
        }

        return packet_info;
    }

    toString(): string {
        return this.type;
    }

}

export class DnsPacket implements SerializableApplicationLayerPacket {
    header: DnsHeader;
    questions: DnsQuestion[];
    answers: DnsResourceRecord[];
    nameservers: DnsResourceRecord[];
    additional: DnsResourceRecord[];
    type: string;

    constructor(header: any, questions: any[], answers: any[], nameservers: any[], additional: any[]) {
        this.header = new DnsHeader(
            header.id,
            header.query,
            header.opcode,
            header.authoritative,
            header.truncated,
            header.recursion_desired,
            header.recursion_available,
            header.authenticated_data,
            header.checking_disabled,
            header.response_code,
            header.num_questions,
            header.num_answers,
            header.num_nameservers,
            header.num_additional
        );

        let quest: DnsQuestion[] = [];
        questions.forEach((q) => {
            quest.push(new DnsQuestion(
                q.query_name,
                q.prefer_unicast,
                q.query_type,
                q.query_class
            ))
        });
        this.questions = quest;

        let ans: DnsResourceRecord[] = [];
        answers.forEach((a) => {
            ans.push(new DnsResourceRecord(
                a.name,
                a.multicast_unique,
                a.class,
                a.ttl,
                a.data
            ))
        });
        this.answers = ans;

        let ns: DnsResourceRecord[] = [];
        nameservers.forEach((n) => {
            ns.push(new DnsResourceRecord(
                n.name,
                n.multicast_unique,
                n.class,
                n.ttl,
                n.data
            ))
        });
        this.nameservers = ns;

        let add: DnsResourceRecord[] = [];
        additional.forEach((a) => {
            add.push(new DnsResourceRecord(
                a.name,
                a.multicast_unique,
                a.class,
                a.ttl,
                a.data
            ))
        });
        this.additional = add;

        this.type = "Domain Name System";
    }

    getInfo(): string {
        if (this.header.query) {
            let questions_name : String = "[";

            for (let i = 0; i < this.questions.length; i++)
                questions_name += this.questions[i].query_name +",";

            questions_name = questions_name.substring(0, questions_name.length - 1);
            questions_name += "]";

            return "Standard query (0x" + this.header.id.toString(16) + ") " + questions_name;
        }
        else
            return "Standard query response (0x" + this.header.id.toString(16) + ")"
    }

    getType(): string {
        return "DNS";
    }

    toDisplay(): any {
        let questions: any[] = [];
        this.questions.forEach((q) => questions.push(q.toDisplay()));

        let answers: any[] = [];
        this.answers.forEach((a) => answers.push(a.toDisplay()));

        let nameservers: any[] = [];
        this.nameservers.forEach((n) => nameservers.push(n.toDisplay()));

        let additional: any[] = [];
        this.additional.forEach((a) => additional.push(a.toDisplay()));

        return {
            header: this.header.toDisplay(),
            questions: questions,
            answers: answers,
            nameservers: nameservers,
            additional: additional
        };
    }

    toString(): string {
        if (this.header.query)
            return "Domain Name System (query)"
        else
            return "Domain Name System (response)"
    }
}