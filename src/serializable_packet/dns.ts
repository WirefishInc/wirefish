export class DnsHeader {
    id: number;
    query: boolean;
    opcode: string;
    authoritative: boolean;
    truncated: boolean;
    recursion_desired: boolean;
    recursion_available: boolean;
    authenticated_data: boolean;
    checking_disabled: boolean;
    response_code: string;
    num_questions: number;
    num_answers: number;
    num_nameservers: number;
    num_additional: number;

    constructor(
        id: number,
        query: boolean,
        opcode: string,
        authoritative: boolean,
        truncated: boolean,
        recursion_desired: boolean,
        recursion_available: boolean,
        authenticated_data: boolean,
        checking_disabled: boolean,
        response_code: string,
        num_questions: number,
        num_answers: number,
        num_nameservers: number,
        num_additional: number,
    ) {
        this.id = id;
        this.query = query;
        this.opcode = opcode;
        this.authoritative = authoritative;
        this.truncated = truncated;
        this.recursion_desired = recursion_desired;
        this.recursion_available = recursion_available;
        this.authenticated_data = authenticated_data;
        this.checking_disabled = checking_disabled;
        this.response_code = response_code;
        this.num_questions = num_questions;
        this.num_answers = num_answers;
        this.num_nameservers = num_nameservers;
        this.num_additional = num_additional;
    }

    toDisplay(): any[] {
        let result = [];

        result.push({"Transaction ID": this.id})
        result.push({"Opcode": this.opcode})
        result.push({"Auhtoritative": String(this.authoritative)})
        result.push({"Truncated": String(this.truncated)})
        result.push({"Recursion desired": String(this.recursion_desired)})
        result.push({"Recursion available": String(this.recursion_available)})
        result.push({"Authenticated data": String(this.authenticated_data)})
        result.push({"Checking Disabled": String(this.checking_disabled)})
        result.push({"Response code": this.response_code})
        result.push({"Number of question": this.num_questions})
        result.push({"Number of answer": this.num_answers})
        result.push({"Number of name servers": this.num_nameservers})
        result.push({"Number of additional": this.num_additional})

        return result;
    }
}

export class DnsQuestion {
    query_name: string;
    prefer_unicast: boolean;
    query_type: string;
    query_class: string;

    constructor(query_name: string,
                prefer_unicast: boolean,
                query_type: string,
                query_class: string) {
        this.query_name = query_name;
        this.prefer_unicast = prefer_unicast;
        this.query_type = query_type;
        this.query_class = query_class;
    }

    toDisplay(): any {
        let result = [];

        result.push({"Prefer Unicast": String(this.prefer_unicast)})
        result.push({"Query Type": this.query_type})
        result.push({"Query Class": this.query_class})

        return {name: this.query_name, fields: result};
    }
}

export class DnsResourceRecord {
    name: string;
    multicast_unique: boolean;
    class_: string;
    ttl: number;
    data: ResourceData;

    constructor(
        name: string,
        multicast_unique: boolean,
        _class: string,
        ttl: number,
        data: any
    ) {
        this.name = name;
        this.multicast_unique = multicast_unique;
        this.class_ = _class;
        this.ttl = ttl;

        switch (data.type) {
            case "A":
                this.data = new A(data.address)
                break;
            case "AAAA":
                this.data = new Aaaa(data.address)
                break;
            case "CNAME":
                this.data = new Cname(data.name)
                break;
            case "MX":
                this.data = new Mx(data.preference, data.exchange)
                break;
            case "NS":
                this.data = new Ns(data.name)
                break;
            case "PTR":
                this.data = new Ptr(data.name)
                break;
            case "SOA":
                this.data = new Soa(data.primary_ns, data.mailbox, data.serial, data.refresh, data.retry, data.expire, data.minimum_ttl)
                break;
            case "SRV":
                this.data = new Srv(data.priority, data.weight, data.port, data.target)
                break;
            case "TXT":
                this.data = new Txt(data.data);
                break;
            case "Unknown":
                this.data = new Unknown(data.data);
                break;
            default:
                this.data = new Unknown(data.data);
        }
    }

    toDisplay() : any {
        let result = [];

        result.push({"Multicas Unique": String(this.multicast_unique)})
        result.push({"Class": this.class_})
        result.push({"TTL": this.ttl})

        return {name: this.name, fields: result, data: this.data.toDisplay()};
    }
}

interface ResourceData {
    type: string;

    toDisplay(): any[]
}

class A implements ResourceData {
    address: string;
    type: string;

    constructor(address: string) {
        this.address = address;
        this.type = "A"
    }

    toDisplay() : any[] {
        let result = [];

        result.push({"Type": this.type})
        result.push({"Address": this.address})

        return result
    }
}

class Aaaa implements ResourceData {
    address: string;
    type: string;

    constructor(address: string) {
        this.address = address;
        this.type = "AAAA"
    }

    toDisplay() : any[] {
        let result = [];

        result.push({"Type": this.type})
        result.push({"Address": this.address})

        return result
    }
}

class Cname implements ResourceData {
    name: string;
    type: string;

    constructor(name: string) {
        this.name = name;
        this.type = "CNAME"
    }

    toDisplay() : any[] {
        let result = [];

        result.push({"Type": this.type})
        result.push({"Name": this.name})

        return result
    }
}

class Mx implements ResourceData {
    preference: number;
    exchange: string;
    type: string;

    constructor(preference: number, exchange: string) {
        this.preference = preference;
        this.exchange = exchange;
        this.type = "MX"
    }

    toDisplay() : any[] {
        let result = [];

        result.push({"Type": this.type})
        result.push({"Preference": this.preference})
        result.push({"Exchange": this.exchange})

        return result
    }
}

class Ns implements ResourceData {
    name: string;
    type: string;

    constructor(name: string) {
        this.name = name;
        this.type = "NS"
    }

    toDisplay() : any[] {
        let result = [];

        result.push({"Type": this.type})
        result.push({"Name": this.name})

        return result
    }
}

class Ptr implements ResourceData {
    name: string;
    type: string;

    constructor(name: string) {
        this.name = name;
        this.type = "PTR"
    }

    toDisplay() : any[] {
        let result = [];

        result.push({"Type": this.type})
        result.push({"Name": this.name})

        return result
    }
}

class Soa implements ResourceData {
    primary_ns: string;
    mailbox: string;
    serial: number;
    refresh: number;
    retry: number;
    expire: number;
    minimum_ttl: number;
    type: string;

    constructor(primary_ns: string,
                mailbox: string,
                serial: number,
                refresh: number,
                retry: number,
                expire: number,
                minimum_ttl: number
    ) {
        this.primary_ns = primary_ns;
        this.mailbox = mailbox;
        this.serial = serial;
        this.refresh = refresh;
        this.retry = retry;
        this.expire = expire;
        this.minimum_ttl = minimum_ttl;
        this.type = "SOA"
    }

    toDisplay() : any[] {
        let result = [];

        result.push({"Type": this.type})
        result.push({"Primary NS": this.primary_ns})
        result.push({"Mailbox": this.mailbox})
        result.push({"Serial": this.serial})
        result.push({"Refresh": this.refresh})
        result.push({"Retry": this.retry})
        result.push({"Expire": this.expire})
        result.push({"Minimum TTL": this.minimum_ttl})

        return result
    }
}

class Srv implements ResourceData {
    priority: number;
    weight: number;
    port: number;
    target: string;
    type: string;

    constructor(
        priority: number,
        weight: number,
        port: number,
        target: string
    ) {
        this.priority = priority;
        this.weight = weight;
        this.port = port;
        this.target = target;
        this.type = "SRV";
    }

    toDisplay() : any[] {
        let result = [];

        result.push({"Type": this.type})
        result.push({"Priority": this.priority})
        result.push({"Weight": this.weight})
        result.push({"Port": this.port})
        result.push({"Target": this.target})

        return result
    }
}

class Txt implements ResourceData {
    data: number[]
    type: string;

    constructor(data: number[]) {
        this.data = data;
        this.type = "TXT"
    }

    toDisplay() : any[] {
        let result = [];

        result.push({"Type": this.type})
        result.push({"Data": this.data})

        return result
    }
}

class Unknown implements ResourceData {
    data: number[]
    type: string;

    constructor(data: number[]) {
        this.data = data;
        this.type = "Unknown"
    }

    toDisplay() : any[] {
        let result = [];

        result.push({"Type": this.type})
        result.push({"Data": this.data})

        return result
    }
}