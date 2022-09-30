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
        packet_info.push({"Payload": this.payload.toString()});
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
        return [{"Data": this.data.toString()}]
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
    version: string;
    message_type: string;
    type: string;

    constructor(data: number[], version: string, message_type: string) {
        this.data = data;
        this.version = version;
        this.message_type = message_type;
        this.type = "Encrypted"
    }

    toDisplay(): any {
        return [{"Version": this.version}, {"Message Type": this.message_type}, {"Data": this.data.toString()}];
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

export class CustomMalformedMessage implements CustomTlsMessages {
    version: string;
    message_type: string;
    error_type: string;
    error: string;
    data: number[];
    type: string;

    constructor(version: string, message_type: string, error_type: any, data: number[]) {
        this.version = version;
        this.message_type = message_type;
        this.error_type = error_type.type;
        this.error = error_type.error;
        this.data = data;
        this.type = "TLS Malformed"
    }

    getType(): string {
        return this.type;
    }

    toDisplay(): any {
        let packet_info = [];

        packet_info.push({"Version": this.version});
        packet_info.push({"Message Type": this.message_type});
        packet_info.push({"Error Type": this.error_type});
        packet_info.push({"Error": this.error});
        packet_info.push({"Data": this.data.toString()});

        return packet_info;
    }

    toString(): string {
        return "TLS Malformed Packet";
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
        packet_info.push({"Rand Data": this.rand_data.toString()});
        packet_info.push({"Session Id": this.session_id.toString()});
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
        packet_info.push({"Rand Data": this.rand_data.toString()});
        packet_info.push({"Session Id": this.session_id.toString()});
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

        packet_info.push({"Signature Algorithm": this.signature_algorithm});
        packet_info.push({"Signature Value": this.signature_value.toString()});
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
        let res: Certificate[] = [];
        certificates.forEach((c) => {
            res.push(new Certificate(
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
        let packet_info: any;
        let res: any[] = [];
        this.certificates.forEach((c) => res.push(c.toDisplay()))

        packet_info = {"certificateList": res}

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

        packet_info.push({"Signature Hash Alogs": this.sig_hash_algos.toString()});

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
    status_type: string;
    data: number[];
    type: string;

    constructor(status_type: string, data: number[]) {
        super();
        this.status_type = status_type;
        this.data = data;
        this.type = "Certificate Status"
    }

    toDisplay(): any {
        let packet_info = [];

        packet_info.push({"Status Type": this.status_type});
        packet_info.push({"Data": this.data.toString()});

        return packet_info;
    }

    toString(): string {
        let res = super.toString();

        return res + "Protocol: Certificate Status";
    }

    getType(): string {
        return this.type
    }
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

        packet_info.push({"Data": this.data.toString()});

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

        packet_info.push({"Data": this.data.toString()});

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

        packet_info.push({"Ticket": this.ticket.toString()});
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

        packet_info.push({"Selected Protocol": this.selected_protocol.toString()});
        packet_info.push({"Padding": this.padding.toString()});

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

        packet_info.push({"Data": this.data.toString()});

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
        packet_info.push({"Random": this.random.toString()});
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

function separateObject(obj: any) {
    const res: any[] = [];
    const keys = Object.keys(obj);
    keys.forEach(key => {
        let object = {};
        // @ts-ignore
        object[key] = obj[key];
        res.push(object);
    });
    return res;
}


export class ClientKeyExchangeMessage extends CustomHandshakeMessage {
    parameters: ClientParameters | number[];
    param_type: string;
    type: string;

    constructor(param: any) {
        super();
        this.type = "Client Key Exchange";
        this.param_type = param.type;
        switch (param.type) {
            case "Dh":
                this.parameters = new ServerDhParameters(
                    param.parameters.prime_modulus,
                    param.parameters.generator,
                    param.parameters.public_value
                )
                break;
            case "Ec":
                this.parameters = new ServerEcParameters(
                    param.parameters.ec_type,
                    param.parameters.ec_content
                )
                break;
            case "Ecdh":
                this.parameters = new ClientEcdhParameters(param.parameters.point)
                break;
            default:
                this.parameters = param.parameters
        }
    }

    toDisplay(): any[] {
        let result: any[] = [];

        if (Array.isArray(this.parameters))
            result.push({"Parameters": this.parameters.toString()})
        else
            result = separateObject(this.parameters.toDisplay())

        result.unshift({"Parameters Type": this.param_type})

        return result
    }

    toString(): string {
        let res = super.toString();

        return res + "Protocol: Client Key Exchange";
    }

    getType(): string {
        return this.type
    }
}


export class ServerKeyExchangeMessage extends CustomHandshakeMessage {
    parameters: ServerParameters | number[];
    param_type: string;
    type: string;

    constructor(param: any) {
        super();
        this.type = "Server Key Exchange";
        this.param_type = param.type;
        switch (param.type) {
            case "Dh":
                this.parameters = new ServerDhParameters(
                    param.parameters.prime_modulus,
                    param.parameters.generator,
                    param.parameters.public_value
                )
                break;
            case "Ec":
                this.parameters = new ServerEcParameters(
                    param.parameters.ec_type,
                    param.parameters.ec_content
                )
                break;
            case "Ecdh":
                this.parameters = new ServerEcdhParameters(
                    param.parameters.public_point,
                    param.parameters.curve
                )
                break;
            default:
                this.parameters = param.parameters
        }
    }

    toDisplay(): any[] {
        let result: any[] = [];

        if (Array.isArray(this.parameters))
            result.push({"Parameters": this.parameters.toString()})
        else
            result = separateObject(this.parameters.toDisplay())

        result.unshift({"Parameters Type": this.param_type})

        return result
    }

    toString(): string {
        let res = super.toString();

        return res + "Protocol: Server Key Exchange";
    }

    getType(): string {
        return this.type
    }
}

/* --- */

interface ClientParameters {
    toDisplay(): any
}

interface ServerParameters {
    toDisplay(): any
}

class ServerDhParameters implements ClientParameters, ServerParameters {
    prime_modulus: number[];
    generator: number[];
    public_value: number[];

    constructor(
        prime_modulus: number[],
        generator: number[],
        public_value: number[]) {
        this.prime_modulus = prime_modulus;
        this.generator = generator;
        this.public_value = public_value;
    }

    toDisplay(): any {
        let result: any;

        result = {
            "Prime Modulus": this.prime_modulus.toString(),
            "Generator": this.generator.toString(),
            "Public Value": this.public_value.toString()
        }

        return result;
    }
}

class ServerEcParameters implements ClientParameters, ServerParameters {
    ec_type: string;
    ec_content: CustomEcContent | null;

    constructor(ec_type: string, ec_content: any) {
        this.ec_type = ec_type;
        switch (ec_content.type) {
            case "ExplicitPrime":
                this.ec_content = new CustomExplicitPrime(
                    ec_content.content.prime_p,
                    ec_content.content.curve,
                    ec_content.content.base_point,
                    ec_content.content.order,
                    ec_content.content.cofactor
                )
                break;
            case "NamedGroup":
                this.ec_content = new CustomNamedGroup(
                    ec_content.content.group
                )
                break;
            default:
                this.ec_content = null;
        }
    }

    toDisplay(): any {
        let result: any;

        if (this.ec_content)
            result = {"Ec Type": this.ec_type, ...this.ec_content.toDisplay()}
        else
            result = {"Ec Type": this.ec_type}

        return result;
    }
}

class ClientEcdhParameters implements ClientParameters {
    point: string;

    constructor(point: string) {
        this.point = point;
    }

    toDisplay(): any {
        let result: any;

        result = {"Point": this.point}

        return result;
    }
}

class ServerEcdhParameters implements ServerParameters {
    public_point: number[];
    curve: ServerEcParameters;

    constructor(public_point: number[], curve: any) {
        this.public_point = public_point;
        this.curve = new ServerEcParameters(
            curve.ec_type,
            curve.ec_content
        );
    }

    toDisplay(): any {
        let result: any;

        result = {"Public Point": this.public_point.toString(), ...this.curve.toDisplay()}

        return result;
    }
}

/* --- */

interface CustomEcContent {
    toDisplay(): any
}

class CustomExplicitPrime implements CustomEcContent {
    prime_p: number[];
    curve: number[][];
    base_point: number[];
    order: number[];
    cofactor: number[];

    constructor(
        prime_p: number[],
        curve: number[][],
        base_point: number[],
        order: number[],
        cofactor: number[]) {
        this.prime_p = prime_p;
        this.curve = curve;
        this.base_point = base_point;
        this.order = order;
        this.cofactor = cofactor;
    }

    toDisplay(): any {
        let result: any;

        result = {
            "Prime": this.prime_p.toString(),
            "Curve": this.curve.toString(),
            "Base Point": this.base_point.toString(),
            "Order": this.order.toString(),
            "Cofactor": this.cofactor.toString()
        }

        return result;
    }
}

class CustomNamedGroup implements CustomEcContent {
    group: string;

    constructor(group: string) {
        this.group = group;
    }

    toDisplay(): any {
        let result: any;

        result = {"Group": this.group}

        return result;
    }
}
