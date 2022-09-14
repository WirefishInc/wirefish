import {MalformedPacket, SerializableApplicationLayerPacket} from "../types/sniffing";
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
    CustomHeartbeatMessage,
    CustomTlsMessages,
    EndOfEarlyData,
    FinishedMessage,
    HelloRequest,
    HelloRetryRequestMessage,
    KeyUpdate, NewSessionTicketMessage, NextProtocolMessage, ServerDoneMessage,
    ServerHelloMessage, ServerHelloV13Draft18Message, ServerKeyExchangeMessage
} from "./tls";
import {DnsHeader, DnsQuestion, DnsResourceRecord} from "./dns";

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
                    result.push(new CustomEncryptedMessage(message.data))
                    break;
                case "ChangeCipherSpec":
                    result.push(new ChangeCipherSpecMessage())
                    break;
                case "Handshake":
                    let packet = TlsPacket.set_subtype_packet(message);
                    if (packet)
                        result.push(packet)
                    break;
                default:
                    result.push(new MalformedPacket())
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
                    p.ciphers,
                    p.compressions,
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
                result = new CertificateStatusMessage()
                break;
            case "CertificateVerify":
                result = new CertificateVerifyMessage(p.data)
                break;
            case "ClientKeyExchange":
                result = new ClientKeyExchangeMessage(
                    p.data,
                    p.algo_type
                )
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
            case "ServerKeyExchange":
                result = new ServerKeyExchangeMessage(
                    p.prime_modulus,
                    p.generator,
                    p.public_value
                )
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

    toDisplay() {
        return this.messages;
    }

    toString(): string {
        return this.version + " Transport Layer Security"
    }
}

export class HttpResponsePacket implements SerializableApplicationLayerPacket {
    version: number;
    code: number;
    reason: string;
    headers: [[string, string]];
    payload: number[] | string;
    payload_type: string;
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

        switch (payload.type) {
            case "TextCorrectlyDecoded":
                this.payload = payload.content;
                this.payload_type = "Text Correctly Decoded"
                break;
            case "TextMalformedDecoded":
                this.payload = payload.content;
                this.payload_type = "Text Malformed Decoded"
                break;
            case "TextDefaultDecoded":
                this.payload = payload.content;
                this.payload_type = "Text Default Decoded"
                break;
            case "Image":
                this.payload = payload.content;
                this.payload_type = "Image"
                break;
            case "Unknown":
                this.payload = payload.content;
                this.payload_type = "Unknown"
                break;
            case "Encoded":
                this.payload = payload.content;
                this.payload_type = "Encoded"
                break;
            case "Multipart":
                this.payload = payload.content;
                this.payload_type = "Multipart"
                break;
            default:
                this.payload = [];
                this.payload_type = ""
        }

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

        packet_info.push({"HTTPResp": {"type": this.payload_type, "content": this.payload}})

        return packet_info;
    }

    toString(): string {
        return this.type;
    }

}


// TODO Does HttpContentType make sense for Request Packet (no payload)?

export class HttpRequestPacket implements SerializableApplicationLayerPacket {
    method: string;
    path: string;
    version: number;
    headers: [[string, string]];
    type: string;

    constructor(
        method: string,
        path: string,
        version: number,
        headers: [[string, string]]
    ) {
        this.method = method;
        this.path = path;
        this.version = version;
        this.headers = headers;

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

// TODO BUG
// number of additional in field 8 -> displayed 0
// number of answer in field 8 -> displayed 16

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
            ans.push(new DnsResourceRecord(
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

    // TODO: improve getInfo
    getInfo(): string {
        if (this.header.query)
            return "Standard query 0x" + this.header.id.toString(16)
        else
            return "Standard query response 0x" + this.header.id.toString(16)
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