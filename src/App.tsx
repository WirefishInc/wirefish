import {ThemeProvider, createTheme} from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import {useState, useEffect} from 'react';
import {
    Accordion, AccordionDetails, AccordionSummary, Alert, Fab, FormControl, Grid, List, Snackbar
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import {PlayArrow, Stop, Pause, RestartAlt} from '@mui/icons-material';
import {DataGrid, GridColDef} from '@mui/x-data-grid';
import './index.css';
import API from './API';
import InterfaceInput from './components/InterfaceInput';
import TimeIntervalInput from './components/TimeIntervalInput';
import CloseIcon from '@mui/icons-material/Close';
import ReportFolderInput from "./components/ReportFolderInput";
import ReportNameInput from "./components/ReportNameInput";
import ToggleButton from "./components/ToggleButton";
import {SniffingStatus, GeneralPacket} from "./types/sniffing";
import {Fields, TlsFields} from "./components/Fields";
import HewViewer from "./components/HexViewer";
import InputLabel from '@mui/material/InputLabel';
import MenuItem from '@mui/material/MenuItem';
import Select from '@mui/material/Select';

const darkTheme = createTheme({
    palette: {
        mode: 'dark',
    },
});

const columns: GridColDef[] = [
    {field: 'id', headerName: '#', width: 70},
    {field: 'type', headerName: 'Type', width: 100, valueGetter: p => p.row.type},
    {field: 'sourceMAC', headerName: 'Source MAC', width: 200, valueGetter: p => p.row.sourceMAC},
    {
        field: 'destinationMAC',
        headerName: 'Destination MAC',
        width: 200,
        valueGetter: p => p.row.destinationMAC
    },
    {
        field: 'sourceIP',
        headerName: 'Source IP',
        width: 200,
        valueGetter: p => p.row.sourceIP
    },
    {
        field: 'destinationIP',
        headerName: 'Destination IP',
        width: 200,
        valueGetter: p => p.row.destinationIP
    },
    {field: 'length', headerName: 'Lenght', width: 70, valueGetter: p => p.row.length},
    {field: 'info', headerName: 'Info', width: 1000, valueGetter: p => p.row.info},
];

function App() {
    let [interfaces, setInterfaces] = useState<string[] | null>(null);
    let [currentInterface, setCurrentInterface] = useState<string>("");
    let [sniffingStatus, setSniffingStatus] = useState<SniffingStatus>(SniffingStatus.Inactive);
    let [capturedPackets, setCapturedPackets] = useState<GeneralPacket[]>([]);
    let [reportUpdateTime, setReportUpdateTime] = useState<number>(30);
    let [reportFileName, setReportFileName] = useState<string>("report");
    let [reportFolder, setReportFolder] = useState<string>("./");
    let [errorMessage, setErrorMessage] = useState<string>("");
    let [selectedPacket, setSelectedPacket] = useState<GeneralPacket | null>(null);
    let [over, setOver] = useState<string | null>(null);
    let [filter, setFilter] = useState<string>("ALL");

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
                setCapturedPackets(packets => {
                    return [...packets, new GeneralPacket(packets.length, packet)];
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

    // TODO: more filters
    const packetFilter = (packet: GeneralPacket) => {
        switch (filter) {
            case 'ALL':
                return true

            case 'TLS':
                return packet.type === 'TLS'

            case 'TCP':
                return packet.type === 'TCP'

            case 'UDP':
                return packet.type === 'UDP'

            case 'ICMPv6':
                return packet.type === 'ICMPv6'

            case 'ICMP':
                return packet.type === 'ICMP'

            case 'ARP':
                return packet.type === 'ARP'

            case 'HTTP':
                return packet.type === 'HTTP'

            default:
                return true
        }
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

                {/* Filter */}
                <Grid xs={12} item={true} className={"container-center"}>
                    <FormControl >
                        <InputLabel id="select-label">Type</InputLabel>
                        <Select
                            labelId="select-label"
                            id="select"
                            value={filter}
                            label="Type"
                            onChange={(ev) => setFilter(ev.target.value)}
                        >
                            <MenuItem value={"ALL"}>All packet</MenuItem>
                            <MenuItem value={"TLS"}>TLS packet</MenuItem>
                            <MenuItem value={"TCP"}>TCP packet</MenuItem>
                            <MenuItem value={"UDP"}>UDP packet</MenuItem>
                            <MenuItem value={"ICMPv6"}>ICMPv6 packet</MenuItem>
                            <MenuItem value={"ICMP"}>ICMP packet</MenuItem>
                            <MenuItem value={"ARP"}>ARP packet</MenuItem>
                            <MenuItem value={"HTTP"}>HTTP packet</MenuItem>
                        </Select>
                    </FormControl>
                </Grid>

                {/* Sniffing Results */}

                <Grid xs={12} item={true}>
                    <DataGrid style={{marginTop: "15px", minHeight: "250px"}}
                              rows={capturedPackets.filter(packetFilter)} columns={columns}
                              onCellClick={(ev) => setSelectedPacket(ev.row)}/>
                </Grid>

                <Snackbar anchorOrigin={{vertical: "bottom", horizontal: "right"}} open={errorMessage.length > 0}
                          key={errorMessage} onClick={() => setErrorMessage("")}>
                    <Alert severity="error">
                        {errorMessage}
                    </Alert>
                </Snackbar>

                {/* Info selected Packet */}

                {
                    !selectedPacket ? null :
                        <>
                            <Fab className={"close-btn"} size={"small"}
                                 onClick={() => setSelectedPacket(null)}><CloseIcon/></Fab>
                            <Grid xs={12} item={true}>
                                {!selectedPacket.packet.link_layer_packet ? null :
                                    <Accordion>
                                        <AccordionSummary expandIcon={<ExpandMoreIcon/>}>
                                            {selectedPacket.packet.link_layer_packet?.toString()}
                                        </AccordionSummary>
                                        <AccordionDetails>
                                            <List component="nav" aria-label="mailbox folders">
                                                <Fields
                                                    packetInfo={selectedPacket.packet.link_layer_packet.toDisplay()}/>
                                            </List>
                                        </AccordionDetails>
                                    </Accordion>
                                }
                                {!selectedPacket.packet.network_layer_packet ? null :
                                    <Accordion>
                                        <AccordionSummary expandIcon={<ExpandMoreIcon/>}>
                                            {selectedPacket.packet.network_layer_packet?.toString()}
                                        </AccordionSummary>
                                        <AccordionDetails>
                                            <List component="nav" aria-label="mailbox folders">
                                                <Fields
                                                    packetInfo={selectedPacket.packet.network_layer_packet.toDisplay()}/>
                                            </List>
                                        </AccordionDetails>
                                    </Accordion>
                                }
                                {!selectedPacket.packet.transport_layer_packet ? null :
                                    <Accordion>
                                        <AccordionSummary expandIcon={<ExpandMoreIcon/>}>
                                            {selectedPacket.packet.transport_layer_packet?.toString()}
                                        </AccordionSummary>
                                        <AccordionDetails>
                                            <List component="nav" aria-label="mailbox folders">
                                                <Fields
                                                    packetInfo={selectedPacket.packet.transport_layer_packet.toDisplay()}/>
                                            </List>
                                        </AccordionDetails>
                                    </Accordion>
                                }
                                {!selectedPacket.packet.application_layer_packet ? null :
                                    <Accordion>
                                        <AccordionSummary expandIcon={<ExpandMoreIcon/>}>
                                            {selectedPacket.packet.application_layer_packet?.toString()}
                                        </AccordionSummary>
                                        <AccordionDetails>
                                            <List component="nav" aria-label="mailbox folders">
                                                {
                                                    selectedPacket.packet.application_layer_packet.getType() !== "TLS" ?
                                                        <Fields
                                                            packetInfo={selectedPacket.packet.application_layer_packet.toDisplay()}/>
                                                        :
                                                        <TlsFields
                                                            packetInfo={selectedPacket.packet.application_layer_packet.toDisplay()}/>
                                                }
                                            </List>
                                        </AccordionDetails>
                                    </Accordion>
                                }

                            </Grid>
                        </>
                }

                {/* Payload (hex viewer) */}

                {!selectedPacket ? null :
                    <HewViewer
                        over={over}
                        setOver={setOver}
                        payload={!selectedPacket.packet.link_layer_packet ? [] : selectedPacket.packet.link_layer_packet.getPayload()}/>}

            </Grid>
        </ThemeProvider>
    );

}

export default App;
