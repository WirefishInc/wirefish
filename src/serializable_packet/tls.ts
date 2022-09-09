export interface CustomTlsMessages {
    type: string;

    getType(): string;

    toDisplay(): any;

    toString(): string;
}

// todo check all packet without payload !!!

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

        packet_info.push( {"Severity" : this.severity});
        packet_info.push( {"Description" : this.description});

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

        packet_info.push( {"Heartbeat type" : this.heartbeat_type});
        packet_info.push( {"Payload" : this.payload});
        packet_info.push( {"Payload Len" : this.payload_len});

        return packet_info;
    }

    toString(): string {
        return "TLS Record Layer: Heartbeat";
    }

    getType(): string {
        return this.type;
    }
}

// todo
export class CustomHandshakeMessage implements CustomTlsMessages {
    type: string;

    constructor() {
        this.type = "Handshake";
    }

    toDisplay(): any {
    }

    toString(): string {
        return "";
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
        return [ {"Data": this.data}]
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
        return [{"Hardware Type" : this.data}];
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
    }
}

export class Certificate extends CustomHandshakeMessage {
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
        super();
        this.signature_algorithm = signature_algorithm;
        this.signature_value = signature_value;
        this.serial = serial;
        this.issuer_uid = issuer_uid;
        this.subject = subject;
        this.subject_uid = subject_uid;
        this.validity = validity;
        this.version = version;
    }
}

export class CertificateMessage extends CustomHandshakeMessage {
    certificates: Certificate[];

    constructor(certificates: Certificate[]) {
        super();
        this.certificates = certificates;
    }
}

export class CertificateRequestMessage extends CustomHandshakeMessage {
    sig_hash_algos: number[];

    constructor(sig_hash_algos: number[]) {
        super();
        this.sig_hash_algos = sig_hash_algos;
    }
}

export class CertificateStatusMessage extends CustomHandshakeMessage {
    // TODO
}

export class CertificateVerifyMessage extends CustomHandshakeMessage {
    data: number[];

    constructor(data: number[]) {
        super();
        this.data = data;
    }
}

export class ClientKeyExchangeMessage extends CustomHandshakeMessage {
    data: number[];
    algo_type: string;

    constructor(data: number[], algo_type: string) {
        super();
        this.data = data;
        this.algo_type = algo_type;
    }
}

export class FinishedMessage extends CustomHandshakeMessage {
    data: number[];

    constructor(data: number[]) {
        super();
        this.data = data;
    }
}

export class HelloRetryRequestMessage extends CustomHandshakeMessage {
    cipher: string;
    extensions: string[];
    version: string;

    constructor(cipher: string,
                extensions: string[],
                version: string) {
        super();
        this.cipher = cipher;
        this.extensions = extensions;
        this.version = version;
    }
}

export class NewSessionTicketMessage extends CustomHandshakeMessage {
    ticket: number[];
    ticket_lifetime_hint: number;

    constructor(ticket: number[], ticket_lifetime_hint: number) {
        super();
        this.ticket = ticket;
        this.ticket_lifetime_hint = ticket_lifetime_hint;
    }
}

export class NextProtocolMessage extends CustomHandshakeMessage {
    selected_protocol: number[];
    padding: number[];

    constructor(selected_protocol: number[], padding: number[]) {
        super();
        this.selected_protocol = selected_protocol;
        this.padding = padding;
    }
}

export class ServerDoneMessage extends CustomHandshakeMessage {
    data: number[];

    constructor(data: number[]) {
        super();
        this.data = data;
    }
}

export class ServerHelloV13Draft18Message extends CustomHandshakeMessage {
    version: string;
    random: number[];
    cipher: string;
    extensions: string[];

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
    }
}

export class ServerKeyExchangeMessage extends CustomHandshakeMessage {
    prime_modulus: number[];
    generator: number[];
    public_value: number[];

    constructor(
        prime_modulus: number[],
        generator: number[],
        public_value: number[]
    ) {
        super();
        this.prime_modulus = prime_modulus;
        this.generator = generator;
        this.public_value = public_value;
    }
}

export class KeyUpdate extends CustomHandshakeMessage {
    key: string;

    constructor(key: string) {
        super();
        this.key = key;
    }
}


export class EndOfEarlyData extends CustomHandshakeMessage {
}

export class HelloRequest extends CustomHandshakeMessage {
}
