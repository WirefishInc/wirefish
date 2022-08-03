import { useState, useEffect } from 'react';
import { Button, Container, FormControl, InputLabel, Select, MenuItem, Box } from '@mui/material';
import { DataGrid, GridColDef } from '@mui/x-data-grid';

import API from './API';

class Packet {
    id: number;
    sourceMAC: string;
    destinationMAC: string;

    constructor(id: number, sourceMAC: string, destinationMAC: string) {
        this.id = id;
        this.sourceMAC = sourceMAC;
        this.destinationMAC = destinationMAC;
    }
}

const columns: GridColDef[] = [
    { field: 'id', headerName: '#', width: 90 },
    { field: 'sourceMAC', headerName: 'Source MAC', width: 150 },
    { field: 'destinationMAC', headerName: 'Destination MAC', width: 150 }
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
                    return [...packets, new Packet(packets.length, packet[0], packet[1])];
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
        <Container style={{ paddingTop: "15px", height: 300 }} maxWidth={false}>
            <FormControl fullWidth={true}>
                <InputLabel>Interface</InputLabel>
                <Select value={currentInterface} label="Interface" defaultValue={null} onChange={(e) => selectInterface(e.target.value as string)}>
                    {
                        interfaces?.map((i) => <MenuItem key={i} value={i}>{i}</MenuItem>)
                    }
                </Select>
            </FormControl>
            <Button variant="contained" onClick={switchSniffing} fullWidth={true} style={{ marginTop: "5px" }} disabled={currentInterface === "" ? true : false}>
                {!sniffing ? "Start Sniffing!" : "Stop Sniffing"}
            </Button>
            <DataGrid style={{ marginTop: "10px", height: "400px" }}  rows={capturedPackets} columns={columns} />
        </Container>
    );
}

export default App;
