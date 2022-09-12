export interface CustomTlsMessages {
    type: string;

    getType(): string;

    toDisplay(): any;

    toString(): string;
}

/* type */

export class CustomAlertMessage implements CustomTlsMessages {
    severity: string;
    description: string;
    type: string;

    constructor(severity: string, description: string) {
        this.severity = severity;
        this.description = description;
        this.type = "Alert"
    }

    toDisplay(): any {
        let packet_info = [];

        packet_info.push({"Severity": this.severity});
        packet_info.push({"Description": this.description});

        return packet_info;
    }

    toString(): string {
        return "TLS Record Layer: Alert";
    }

    getType(): string {
        return this.type;
    }
}

export class CustomHeartbeatMessage implements CustomTlsMessages {
    heartbeat_type: string;
    payload: number[];
    payload_len: number;
    type: string;

    constructor(heartbeat_type: string, payload: number[], payload_len: number) {
        this.heartbeat_type = heartbeat_type;
        this.payload = payload;
        this.payload_len = payload_len;
        this.type = "Heartbeat"
    }

    toDisplay(): any {
        let packet_info = [];

        packet_info.push({"Heartbeat type": this.heartbeat_type});
        packet_info.push({"Payload": this.payload});
        packet_info.push({"Payload Len": this.payload_len});

        return packet_info;
    }

    toString(): string {
        return "TLS Record Layer: Heartbeat";
    }

    getType(): string {
        return this.type;
    }
}


export class CustomHandshakeMessage implements CustomTlsMessages {
    type: string;

    constructor() {
        this.type = "Handshake";
    }

    toDisplay(): any {
        return []
    }

    toString(): string {
        return "TLS Record Layer: Handshake ";
    }

    getType(): string {
        return this.type
    }
}

export class CustomApplicationDataMessage implements CustomTlsMessages {
    data: number[];
    type: string;

    constructor(data: number[]) {
        this.data = data;
        this.type = "Application Data"
    }

    toDisplay(): any {
        return [{"Data": this.data}]
    }

    toString(): string {
        return "TLS Record Layer: Application Data";
    }

    getType(): string {
        return this.type
    }
}

export class CustomEncryptedMessage implements CustomTlsMessages {
    data: number[];
    type: string;

    constructor(data: number[]) {
        this.data = data;
        this.type = "Encrypted"
    }

    toDisplay(): any {
        return [{"Hardware Type": this.data}];
    }

    toString(): string {
        return "TLS Record Layer: Encrypted";
    }

    getType(): string {
        return this.type
    }
}

export class ChangeCipherSpecMessage implements CustomTlsMessages {
    type: string;

    constructor() {
        this.type = "Change Chiper Spec";
    }

    toDisplay(): any {
        return [];
    }

    toString(): string {
        return "TLS Record Layer: Change Cipher Spec Protocol: Change Cipher Spec";
    }

    getType(): string {
        return this.type
    }
}


/* subtype */

export class ClientHelloMessage extends CustomHandshakeMessage {
    version: string;
    rand_time: number;
    rand_data: number[];
    session_id: number[]; // option
    ciphers: string[];
    compressions: string[];
    extensions: string[];
    type: string;

    constructor(
        version: string,
        rand_time: number,
        rand_data: number[],
        session_id: number[], // option
        ciphers: string[],
        compressions: string[],
        extensions: string[]
    ) {
        super();
        this.version = version;
        this.rand_time = rand_time;
        this.rand_data = rand_data;
        this.session_id = session_id;
        this.ciphers = ciphers;
        this.compressions = compressions;
        this.extensions = extensions;
        this.type = "Client Hello"
    }

    toDisplay(): any {
        let packet_info = [];

        packet_info.push({"Version": this.version});
        packet_info.push({"Rand Time": this.rand_time});
        packet_info.push({"Rand Data": this.rand_data});
        packet_info.push({"Session Id": this.session_id});
        packet_info.push({"Ciphers": this.ciphers});
        packet_info.push({"Compression": this.compressions});
        packet_info.push({"Extension": this.extensions});

        return packet_info;
    }

    toString(): string {
        let res = super.toString();

        return res + "Protocol: Client Hello";
    }

    getType(): string {
        return this.type
    }
}

export class ServerHelloMessage extends CustomHandshakeMessage {
    version: string;
    rand_time: number;
    rand_data: number[];
    session_id: number[]; // option
    ciphers: string;
    compressions: string;
    extensions: string[];
    type: string;

    constructor(
        version: string,
        rand_time: number,
        rand_data: number[],
        session_id: number[], // option
        ciphers: string,
        compressions: string,
        extensions: string[]
    ) {
        super();
        this.version = version;
        this.rand_time = rand_time;
        this.rand_data = rand_data;
        this.session_id = session_id;
        this.ciphers = ciphers;
        this.compressions = compressions;
        this.extensions = extensions;
        this.type = "Server Hello"
    }

    toDisplay(): any {
        let packet_info = [];

        packet_info.push({"Version": this.version});
        packet_info.push({"Rand Time": this.rand_time});
        packet_info.push({"Rand Data": this.rand_data});
        packet_info.push({"Session Id": this.session_id});
        packet_info.push({"Ciphers": this.ciphers});
        packet_info.push({"Compression": this.compressions});
        packet_info.push({"Extension": this.extensions});

        return packet_info;
    }

    toString(): string {
        let res = super.toString();

        return res + "Protocol: Server Hello";
    }

    getType(): string {
        return this.type
    }
}

class Certificate {
    signature_algorithm: string;
    signature_value: number[];
    serial: string;
    issuer_uid: string;
    subject: string;
    subject_uid: string;
    validity: string;
    version: string;
    //subject_pki: string;

    constructor(
        signature_algorithm: string,
        signature_value: number[],
        serial: string,
        issuer_uid: string,
        subject: string,
        subject_uid: string,
        validity: string,
        version: string,
    ) {
        this.signature_algorithm = signature_algorithm;
        this.signature_value = signature_value;
        this.serial = serial;
        this.issuer_uid = issuer_uid;
        this.subject = subject;
        this.subject_uid = subject_uid;
        this.validity = validity;
        this.version = version;
    }

    toDisplay(): any {
        let packet_info = [];

        packet_info.push({"Signature Algorithm": this.version});
        packet_info.push({"Signature Value": this.signature_value});
        packet_info.push({"Serial": this.serial});
        packet_info.push({"Issuer Id": this.issuer_uid});
        packet_info.push({"Subject": this.subject});
        packet_info.push({"Subject Id": this.subject_uid});
        packet_info.push({"Validity": this.validity});
        packet_info.push({"Version": this.version});

        return packet_info;
    }
}

export class CertificateMessage extends CustomHandshakeMessage {
    certificates: Certificate[];
    type: string;

    constructor(certificates: Certificate[]) {
        super();
        let res : Certificate[] = [];
        certificates.forEach( (c) => {
            res.push( new Certificate(
                c.signature_algorithm,
                c.signature_value,
                c.serial,
                c.issuer_uid,
                c.subject,
                c.subject_uid,
                c.validity,
                c.version
            ))
        })
        this.certificates = res;
        this.type = "Certificate"
    }

    toDisplay(): any {
        let packet_info: any[] = [];

        this.certificates.forEach( (c) => packet_info.push(c.toDisplay()))

        return packet_info;
    }

    toString(): string {
        let res = super.toString();

        return res + "Protocol: Certificate";
    }

    getType(): string {
        return this.type
    }
}

export class CertificateRequestMessage extends CustomHandshakeMessage {
    sig_hash_algos: number[];
    type: string;

    constructor(sig_hash_algos: number[]) {
        super();
        this.sig_hash_algos = sig_hash_algos;
        this.type = "Certificate Request"
    }

    toDisplay(): any {
        let packet_info = [];

        packet_info.push({"Signature Hash Alogs": this.sig_hash_algos});

        return packet_info;
    }

    toString(): string {
        let res = super.toString();

        return res + "Protocol: Certificate Request";
    }

    getType(): string {
        return this.type
    }
}

export class CertificateStatusMessage extends CustomHandshakeMessage {
    // TODO CertificateStatusMessage
}

export class CertificateVerifyMessage extends CustomHandshakeMessage {
    data: number[];
    type: string;

    constructor(data: number[]) {
        super();
        this.data = data;
        this.type = "Certificate Verify"
    }

    toDisplay(): any {
        let packet_info = [];

        packet_info.push({"Data": this.data});

        return packet_info;
    }

    toString(): string {
        let res = super.toString();

        return res + "Protocol: Certificate Verify";
    }

    getType(): string {
        return this.type
    }
}

export class ClientKeyExchangeMessage extends CustomHandshakeMessage {
    data: number[];
    algo_type: string;
    type: string;

    constructor(data: number[], algo_type: string) {
        super();
        this.data = data;
        this.algo_type = algo_type;
        this.type = "Client Key Exchange"
    }

    toDisplay(): any {
        let packet_info = [];

        packet_info.push({"Data": this.data});
        packet_info.push({"Algorithm Type": this.algo_type});

        return packet_info;
    }

    toString(): string {
        let res = super.toString();

        return res + "Protocol: Client Key Exchange";
    }

    getType(): string {
        return this.type
    }
}

export class FinishedMessage extends CustomHandshakeMessage {
    data: number[];
    type: string;

    constructor(data: number[]) {
        super();
        this.data = data;
        this.type = "Finished"
    }

    toDisplay(): any {
        let packet_info = [];

        packet_info.push({"Data": this.data});

        return packet_info;
    }

    toString(): string {
        let res = super.toString();

        return res + "Protocol: Finished";
    }

    getType(): string {
        return this.type
    }
}

export class HelloRetryRequestMessage extends CustomHandshakeMessage {
    cipher: string;
    extensions: string[];
    version: string;
    type: string;

    constructor(cipher: string,
                extensions: string[],
                version: string) {
        super();
        this.cipher = cipher;
        this.extensions = extensions;
        this.version = version;
        this.type = "Hello Retry Request"
    }

    toDisplay(): any {
        let packet_info = [];

        packet_info.push({"Cipher": this.cipher});
        packet_info.push({"Extension": this.extensions});
        packet_info.push({"Version": this.version});

        return packet_info;
    }

    toString(): string {
        let res = super.toString();

        return res + "Protocol: Hello Retry Request";
    }

    getType(): string {
        return this.type
    }
}

export class NewSessionTicketMessage extends CustomHandshakeMessage {
    ticket: number[];
    ticket_lifetime_hint: number;
    type: string;

    constructor(ticket: number[], ticket_lifetime_hint: number) {
        super();
        this.ticket = ticket;
        this.ticket_lifetime_hint = ticket_lifetime_hint;
        this.type = "New Session Ticket"
    }

    toDisplay(): any {
        let packet_info = [];

        packet_info.push({"Ticket": this.ticket});
        packet_info.push({"Ticket Life Time Hint": this.ticket_lifetime_hint});

        return packet_info;
    }

    toString(): string {
        let res = super.toString();

        return res + "Protocol: New Session Ticket";
    }

    getType(): string {
        return this.type
    }
}

export class NextProtocolMessage extends CustomHandshakeMessage {
    selected_protocol: number[];
    padding: number[];
    type: string;

    constructor(selected_protocol: number[], padding: number[]) {
        super();
        this.selected_protocol = selected_protocol;
        this.padding = padding;
        this.type = "Next Protocol"
    }

    toDisplay(): any {
        let packet_info = [];

        packet_info.push({"Selected Protocol": this.selected_protocol});
        packet_info.push({"Padding": this.padding});

        return packet_info;
    }

    toString(): string {
        let res = super.toString();

        return res + "Protocol: Next Protocol";
    }

    getType(): string {
        return this.type
    }
}

export class ServerDoneMessage extends CustomHandshakeMessage {
    data: number[];
    type: string;

    constructor(data: number[]) {
        super();
        this.data = data;
        this.type = "Server Done"
    }

    toDisplay(): any {
        let packet_info = [];

        packet_info.push({"Data": this.data});

        return packet_info;
    }

    toString(): string {
        let res = super.toString();

        return res + "Protocol: Server Done";
    }

    getType(): string {
        return this.type
    }
}

export class ServerHelloV13Draft18Message extends CustomHandshakeMessage {
    version: string;
    random: number[];
    cipher: string;
    extensions: string[];
    type: string;

    constructor(
        version: string,
        random: number[],
        cipher: string,
        extensions: string[]
    ) {
        super();
        this.version = version;
        this.random = random;
        this.cipher = cipher;
        this.extensions = extensions;
        this.type = "Server Hello V13 Draft 18 Message"
    }

    toDisplay(): any {
        let packet_info = [];

        packet_info.push({"Version": this.version});
        packet_info.push({"Random": this.random});
        packet_info.push({"Cipher": this.cipher});
        packet_info.push({"Extensions": this.extensions});

        return packet_info;
    }

    toString(): string {
        let res = super.toString();

        return res + "Protocol: Server Hello V13 Draft 18 Message";
    }

    getType(): string {
        return this.type
    }
}

export class ServerKeyExchangeMessage extends CustomHandshakeMessage {
    prime_modulus: number[];
    generator: number[];
    public_value: number[];
    type: string;

    constructor(
        prime_modulus: number[],
        generator: number[],
        public_value: number[]
    ) {
        super();
        this.prime_modulus = prime_modulus;
        this.generator = generator;
        this.public_value = public_value;
        this.type = "Server Key Exchange"
    }

    toDisplay(): any {
        let packet_info = [];

        packet_info.push({"Prime Modulus": this.prime_modulus});
        packet_info.push({"Generator": this.generator});
        packet_info.push({"Public Value": this.public_value});

        return packet_info;
    }

    toString(): string {
        let res = super.toString();

        return res + "Protocol: Server Key Exchange";
    }

    getType(): string {
        return this.type
    }
}

export class KeyUpdate extends CustomHandshakeMessage {
    key: string;
    type: string;

    constructor(key: string) {
        super();
        this.key = key;
        this.type = "Key Update"
    }

    toDisplay(): any {
        let packet_info = [];

        packet_info.push({"Key": this.key});

        return packet_info;
    }

    toString(): string {
        let res = super.toString();

        return res + "Protocol: Key Update";
    }

    getType(): string {
        return this.type
    }
}


export class EndOfEarlyData extends CustomHandshakeMessage {
    type: string;

    constructor() {
        super();
        this.type = "End of Early Data"
    }

    toDisplay(): any {
        return [];
    }

    toString(): string {
        let res = super.toString();

        return res + "Protocol: End of Early Data";
    }

    getType(): string {
        return this.type
    }
}

export class HelloRequest extends CustomHandshakeMessage {
    type: string;

    constructor() {
        super();
        this.type = "Hello Request"
    }

    toDisplay(): any {
        return [];
    }

    toString(): string {
        let res = super.toString();

        return res + "Protocol: Hello Request";
    }

    getType(): string {
        return this.type
    }
}
