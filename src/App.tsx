import {ThemeProvider, createTheme} from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import {useState, useEffect, FC} from 'react';
import {
    Accordion, AccordionDetails, AccordionSummary, Alert, Divider, Fab, FormControl, Grid, List, ListItem, Snackbar
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

const darkTheme = createTheme({
    palette: {
        mode: 'dark',
    },
});

const columns: GridColDef[] = [
    {field: 'id', headerName: '#', width: 10},
    {field: 'type', headerName: 'Type', width: 140, valueGetter: p => p.row.type},
    {field: 'sourceMAC', headerName: 'Source MAC', width: 140, valueGetter: p => p.row.sourceMAC},
    {
        field: 'destinationMAC',
        headerName: 'Destination MAC',
        width: 140,
        valueGetter: p => p.row.destinationMAC
    },
    {
        field: 'sourceIP',
        headerName: 'Source IP',
        width: 120,
        valueGetter: p => p.row.sourceIP
    },
    {
        field: 'destinationIP',
        headerName: 'Destination IP',
        width: 120,
        valueGetter: p => p.row.destinationIP
    },
    {field: 'length', headerName: 'Lenght', width: 100, valueGetter: p => p.row.packet.length},
    {field: 'info', headerName: 'Info', width: 200, valueGetter: p => p.row.info},
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

    interface FieldProps {
        packetInfo: [];
    }

    const Fields: FC<FieldProps> = ({packetInfo}) => {
        let fields = [];

        for (const el of packetInfo) {
            fields.push(
                <>
                    <ListItem key={fields.length}><> {Object.keys(el)[0]} : {Object.values(el)[0]} </>
                    </ListItem>
                    <Divider/>
                </>
            )
        }

        return (
            <>{fields}</>
        );
    };

    interface HewViewerProps {
        payload: string[];
    }

    const HewViewer: FC<HewViewerProps> = ({payload}) => {
        let clone = Array.from(payload)
        let rows = [];

        while (clone.length) {
            rows.push(clone.splice(0, 16))
        }

        return (
            <table>
                <tbody>
                {rows.map((r, i) =>
                    <tr>
                        {<td className={"index"}>{"0x" + (i * 16).toString(16).toUpperCase()}</td>}
                        {
                            r.map((el, j) =>
                                <td id={(i * 16 + j).toString()}
                                    onMouseOver={(ev) => {
                                        // @ts-ignore
                                        setOver(ev.target.id.toString())
                                    }}
                                    onMouseLeave={(ev) => {
                                        setOver("")
                                    }}
                                    className={over === (i * 16 + j).toString() ? "hex active" : "hex"}>{el}</td>
                            )}
                    </tr>
                )}
                </tbody>
            </table>
        )
    }

    function hex_to_ascii(byte: number) {
        let char = "";

        if (byte > 31 && byte < 127) {
            char = String.fromCharCode(byte);
        } else {
            char = "·";
        }

        return char;
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

                {/* Sniffing Results */}

                <Grid xs={12} item={true}>
                    <DataGrid style={{marginTop: "15px", minHeight: "250px"}}
                              rows={capturedPackets} columns={columns}
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
                            </Grid>
                        </>
                }

                {/* Payload (hex viewer)
                TODO : fix bug table not responsive
                TODO: refactor components in other file
                */}

                {!selectedPacket ? null :
                    <Grid className={"payload"} container xs={12} item={true}>
                        <Grid xs={6}>
                            {selectedPacket?.packet.link_layer_packet ?
                                <HewViewer
                                    payload={selectedPacket.packet.link_layer_packet.payloadToHex().map((el) => el.toUpperCase())}/> : null
                            }
                        </Grid>
                        <Grid xs={6}>
                            {selectedPacket?.packet.link_layer_packet ?
                                <HewViewer
                                    payload={selectedPacket?.packet.link_layer_packet?.getPayload().map((el) => hex_to_ascii(el))}/> : null
                            }
                        </Grid>
                    </Grid>
                }

            </Grid>
        </ThemeProvider>
    )
        ;
}

export default App;
