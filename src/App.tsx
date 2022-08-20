import {useState, useEffect} from 'react';
import {Button, Container, FormControl, InputLabel, Select, MenuItem, Box} from '@mui/material';
import {DataGrid, GridColDef} from '@mui/x-data-grid';

import API from './API';

enum TrafficType {
    Incoming = 1,
    Outgoing
}

class Packet {
    id: number;
    sourceMAC: string;
    destinationMAC: string;
    sourceIP: string;
    destinationIP: string;
    protocol: string;
    trafficType: TrafficType;

    constructor(id: number, sourceMAC: string, destinationMAC: string, sourceIP: string, destinationIP: string, protocol: string, trafficType: TrafficType) {
        this.id = id;
        this.sourceMAC = sourceMAC;
        this.destinationMAC = destinationMAC;
        this.sourceIP = sourceIP;
        this.destinationIP = destinationIP;
        this.protocol = protocol;
        this.trafficType = trafficType;
    }
}

const columns: GridColDef[] = [
    {field: 'id', headerName: '#', width: 90},
    {field: 'sourceMAC', headerName: 'Source MAC', width: 150},
    {field: 'destinationMAC', headerName: 'Destination MAC', width: 150}
];

function App() {
    let [interfaces, setInterfaces] = useState<string[] | null>(null);
    let [currentInterface, setCurrentInterface] = useState<string>("");
    let [sniffing, setSniffing] = useState<boolean>(false);
    let [capturedPackets, setCapturedPackets] = useState<Packet[]>([]);

    useEffect(() => {
        const setup = async () => {
            const interfaces = await API.getInterfacesList();
            setInterfaces(interfaces);

            window.AwesomeEvent.listen("packet_received", (data: string) => {
                let packet: string[] = JSON.parse(data);
                setCapturedPackets(packets => {
                    // TODO: Fill last 4 properties of Packet with real values
                    return [...packets, new Packet(packets.length, packet[0], packet[1], "", "", "", TrafficType.Incoming)];
                });
            });
        };

        setup();
    }, []);

    const selectInterface = async (interfaceName: string) => {
        await API.selectInterface(interfaceName);
        setCurrentInterface(interfaceName);
    }

    const stopSniffing = async () => {
        await API.stopSniffing();
        setSniffing(false);
    }

    const startSniffing = async () => {
        if (currentInterface === null) return;

        await API.startSniffing();
        setSniffing(true);
    }

    const switchSniffing = async () => {
        if (!sniffing) await startSniffing();
        else await stopSniffing();
    }

    return (
        <Container style={{paddingTop: "15px", height: 300}} maxWidth={false}>

            {/* Interface selection */}
            {/* Interface selection */}
            {/* Interface selection */}

            {/* Interface selection */}

            <FormControl fullWidth={true}>
                <InputLabel>Interface</InputLabel>
                <Select value={currentInterface} label="Interface" defaultValue={null}
                        onChange={(e) => selectInterface(e.target.value as string)}>
                    {
                        interfaces?.map((i) => <MenuItem key={i} value={i}>{i}</MenuItem>)
                    }
                </Select>
            </FormControl>

            {/* Sniffing Results */}

            <Button variant="contained" onClick={switchSniffing} fullWidth={true} style={{marginTop: "5px"}}
                    disabled={currentInterface === "" ? true : false}>
                {!sniffing ? "Start Sniffing!" : "Stop Sniffing"}
            </Button>
            <DataGrid style={{marginTop: "10px", height: "400px"}} rows={capturedPackets} columns={columns}/>
        </Container>
    );
}

export default App;
