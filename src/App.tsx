import {ThemeProvider, createTheme} from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import {useState, useEffect} from 'react';
import {Alert, FormControl, Grid, Snackbar} from '@mui/material';
import {PlayArrow, Stop, Pause, RestartAlt} from '@mui/icons-material';
import {DataGrid, GridColDef} from '@mui/x-data-grid';
import './index.css';
import API from './API';
import {Packet, TrafficType, SniffingStatus, SerializablePacket} from "./types/sniffing";
import InterfaceInput from './components/InterfaceInput';
import TimeIntervalInput from './components/TimeIntervalInput';
import ReportFolderInput from "./components/ReportFolderInput";
import ReportNameInput from "./components/ReportNameInput";
import ToggleButton from "./components/ToggleButton";
import {EthernetPacket} from "./serializable_packet/link";
import {ArpPacket, Ipv4Packet, Ipv6Packet} from "./serializable_packet/network";
import {TcpPacket} from "./serializable_packet/transport";

const darkTheme = createTheme({
    palette: {
        mode: 'dark',
    },
});

const columns: GridColDef[] = [
    {field: 'id', headerName: '#', width: 10},
    {field: 'type', headerName: 'Type', width: 140},
    {field: 'sourceMAC', headerName: 'Source MAC', width: 140},
    {field: 'destinationMAC', headerName: 'Destination MAC', width: 140},
    {field: 'sourceIP', headerName: 'Source IP', width: 120},
    {field: 'destinationIP', headerName: 'Destination IP', width: 120},
    {field: 'length', headerName: 'Lenght', width: 50},
    {field: 'info', headerName: 'Info', width: 200},
];

function App() {

    let [interfaces, setInterfaces] = useState<string[] | null>(null);
    let [currentInterface, setCurrentInterface] = useState<string>("");
    let [sniffingStatus, setSniffingStatus] = useState<SniffingStatus>(SniffingStatus.Inactive);
    let [capturedPackets, setCapturedPackets] = useState<Packet[]>([]);
    let [reportUpdateTime, setReportUpdateTime] = useState<number>(30);
    let [reportFileName, setReportFileName] = useState<string>("report");
    let [reportFolder, setReportFolder] = useState<string>("./");
    let [errorMessage, setErrorMessage] = useState<string>("");

    useEffect(() => {
        const setup = async () => {

            /* Interfaces initialization */
            try {
                const interfaces = await API.getInterfacesList();
                setInterfaces(interfaces);
            } catch (exception) {
                setErrorMessage("Unable to retrieve interfaces, try running this App as administrator");
                console.log(exception);
            }

            /* Packet reception event */
            window.AwesomeEvent.listen("packet_received", (packet: any) => {
                let link_layer : SerializablePacket;
                let network_layer: SerializablePacket;
                let transport_layer: SerializablePacket;

                switch (packet.linkLayerPacket.type){
                    case "EthernetPacket":
                        link_layer = packet.linkLayerPacket.packet as EthernetPacket;
                        break;

                    default:
                        console.log("Malformed packet") // todo
                }

                switch (packet.networkLayerPacket.type){
                    case "ArpPacket":
                        network_layer = packet.networkLayerPacket.packet as ArpPacket;
                        break;

                    case "Ipv4Packet":
                        network_layer = packet.networkLayerPacket.packet as Ipv4Packet;
                        break;

                    case "Ipv6Packet":
                        network_layer = packet.networkLayerPacket.packet as Ipv6Packet;
                        break;

                    default:
                        console.log("Malformed packet") // todo
                }

                switch (packet.transportLayerPacket.type){
                    case "TcpPacket":
                        transport_layer = packet.networkLayerPacket.packet as TcpPacket;
                        break;

                    /* ... */
                }

                setCapturedPackets(packets => {
                    return [...packets, new Packet(link_layer, network_layer, transport_layer)];
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
        setSniffingStatus(SniffingStatus.Inactive);
        console.log(capturedPackets) // todo: delete
    }

    const startSniffing = async () => {
        if (currentInterface === null) return;

        await API.startSniffing(`${reportFolder}${reportFileName}.txt`, reportUpdateTime);
        setSniffingStatus(SniffingStatus.Active);
    }

    const pauseSniffing = async () => {
        // TODO: PAUSE
        await API.stopSniffing();
        setSniffingStatus(SniffingStatus.Paused);
    }

    const resumeSniffing = async () => {
        // TODO: RESUME
        if (currentInterface === null) return;

        await API.startSniffing(`${reportFolder}${reportFileName}.txt`, reportUpdateTime);
        setSniffingStatus(SniffingStatus.Active);
    }

    const startStopSniffing = async () => {
        if (sniffingStatus === SniffingStatus.Inactive) await startSniffing();
        else if (sniffingStatus === SniffingStatus.Active) await stopSniffing();
    }

    const pauseResumeSniffing = async () => {
        if (sniffingStatus === SniffingStatus.Paused) await resumeSniffing();
        else if (sniffingStatus === SniffingStatus.Active) await pauseSniffing();
    }

    return (
        <ThemeProvider theme={darkTheme}>
            <CssBaseline/>
            <Grid container spacing={2} className={"container-main"}>

                {/* Interface selection */}

                <Grid xs={12} item={true}>
                    <InterfaceInput currentInterface={currentInterface} interfaces={interfaces}
                                    selectInterface={selectInterface} sniffingStatus={sniffingStatus}/>
                </Grid>

                {/* Time interval selection */}

                <Grid xs={3} item={true}>
                    <TimeIntervalInput reportUpdateTime={reportUpdateTime} sniffingStatus={sniffingStatus}
                                       setReportUpdateTime={setReportUpdateTime}/>
                </Grid>

                {/* Output file selection */}

                <Grid xs={6} item={true}>
                    <ReportFolderInput setReportFolder={setReportFolder} sniffingStatus={sniffingStatus}
                                       reportFolder={reportFolder}/>
                </Grid>
                <Grid xs={3} item={true}>
                    <ReportNameInput setReportFileName={setReportFileName} sniffingStatus={sniffingStatus}
                                     reportFileName={reportFileName}/>
                </Grid>

                {/* Sniffing Controls */}

                <Grid xs={12} item={true}>
                    <FormControl className={"container-center"}>
                        {
                            sniffingStatus !== SniffingStatus.Paused &&
                            <ToggleButton toggleFunction={startStopSniffing} disabled={currentInterface === ""}
                                          condition={sniffingStatus === SniffingStatus.Active}
                                          textTrue={"Stop Sniffing"} textFalse={"Start Sniffing"}
                                          iconTrue={<Stop/>} iconFalse={<PlayArrow/>}
                            />
                        }
                        {
                            sniffingStatus !== SniffingStatus.Inactive &&
                            <ToggleButton toggleFunction={pauseResumeSniffing} disabled={currentInterface === ""}
                                          condition={sniffingStatus === SniffingStatus.Active}
                                          textTrue={"Pause Sniffing"} textFalse={"Resume Sniffing"}
                                          iconTrue={<Pause/>} iconFalse={<RestartAlt/>}
                            />
                        }
                    </FormControl>
                </Grid>

                {/* Sniffing Results

                <Grid xs={12} item={true}>
                    <DataGrid style={{marginTop: "15px", minHeight: "250px"}} rows={capturedPackets} columns={columns}/>
                </Grid>

                */}

                <Snackbar anchorOrigin={{vertical: "bottom", horizontal: "right"}} open={errorMessage.length > 0}
                          key={errorMessage} onClick={() => setErrorMessage("")}>
                    <Alert severity="error">
                        {errorMessage}
                    </Alert>
                </Snackbar>

            </Grid>
        </ThemeProvider>
    );
}

export default App;
