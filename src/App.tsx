import {createTheme, ThemeProvider} from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import React, {useState, useEffect, useRef} from 'react';
import {
    Accordion,
    AccordionDetails,
    AccordionSummary,
    Alert, Checkbox,
    Fab,
    FormControl, FormControlLabel,
    FormGroup, FormLabel,
    Grid,
    LinearProgress,
    List,
    Snackbar, TextField
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import {Pause, PlayArrow, RestartAlt, Stop} from '@mui/icons-material';
import {DataGrid, GridColDef} from '@mui/x-data-grid';
import './index.css';
import API from './API';
import {SniffingStatus, GeneralPacket, FeedbackMessage} from "./types/sniffing";
import InterfaceInput from './components/InterfaceInput';
import TimeIntervalInput from './components/TimeIntervalInput';
import CloseIcon from '@mui/icons-material/Close';
import ReportFolderInput from "./components/ReportFolderInput";
import ReportNameInput from "./components/ReportNameInput";
import ToggleButton from "./components/ToggleButton";
import {Fields, TlsFields} from "./components/Fields";
import HewViewer from "./components/HexViewer";
import Box from "@mui/material/Box";

const darkTheme = createTheme({
    palette: {
        mode: 'dark',
    },
});

const columns: GridColDef[] = [
    {field: 'id', headerName: '#', width: 70, disableColumnMenu: true, sortable: false},
    {
        field: 'type',
        headerName: 'Type',
        width: 100,
        valueGetter: p => p.row.type,
        disableColumnMenu: true,
        sortable: false
    },
    {
        field: 'sourceMAC',
        headerName: 'Source MAC',
        width: 200,
        valueGetter: p => p.row.sourceMAC,
        disableColumnMenu: true,
        sortable: false
    },
    {
        field: 'destinationMAC',
        headerName: 'Destination MAC',
        width: 200,
        valueGetter: p => p.row.destinationMAC, disableColumnMenu: true, sortable: false
    },
    {
        field: 'sourceIP',
        headerName: 'Source IP',
        width: 200,
        valueGetter: p => p.row.sourceIP, disableColumnMenu: true, sortable: false
    },
    {
        field: 'destinationIP',
        headerName: 'Destination IP',
        width: 200,
        valueGetter: p => p.row.destinationIP, disableColumnMenu: true, sortable: false
    },
    {
        field: 'length',
        headerName: 'Lenght',
        width: 70,
        valueGetter: p => p.row.length,
        disableColumnMenu: true,
        sortable: false
    },
    {
        field: 'info',
        headerName: 'Info',
        width: 1000,
        valueGetter: p => p.row.info,
        disableColumnMenu: true,
        sortable: false
    },
];

function App() {

    const REPORT_GENERATION_SECONDS = 30;
    const resetFeedback = {text: "", isError: false, duration: 0};

    let [interfaces, setInterfaces] = useState<string[] | null>(null);
    let [currentInterface, setCurrentInterface] = useState<string>("");
    let [sniffingStatus, setSniffingStatus] = useState<SniffingStatus>(SniffingStatus.Inactive);
    let [capturedPackets, setCapturedPackets] = useState<GeneralPacket[]>([]);
    let [reportUpdateTime, setReportUpdateTime] = useState<number>(REPORT_GENERATION_SECONDS);
    let [reportFileName, setReportFileName] = useState<string>("report");
    let [reportFolder, setReportFolder] = useState<string>("./");
    let [selectedPacket, setSelectedPacket] = useState<GeneralPacket | null>(null);
    let [over, setOver] = useState<string | null>(null);
    let [reportGenerationTimer, setReportGenerationTimer] = useState<null | ReturnType<typeof setInterval>>(null);
    let [reportProgressTimer, setReportProgressTimer] = useState<null | ReturnType<typeof setInterval>>(null);
    let [reportResumeTimeout, setReportResumeTimeout] = useState<null | ReturnType<typeof setTimeout>>(null);
    let [timerRemainingTime, setTimerRemainingTime] = useState<number>(0);
    let [feedbackMessage, setFeedbackMessage] = useState<FeedbackMessage>(resetFeedback);
    let [actionLoading, setActionLoading] = useState<string>("");
    let [reportProgress, setReportProgress] = useState<number>(0);
    let [secondsToReportGeneration, setSecondsToReportGeneration] = useState<number>(REPORT_GENERATION_SECONDS);
    let firstReportGeneration = useRef<boolean>(true);
    let timerStartTime = useRef<number>(0);
    let [srcIpForm, setSrcIpForm] = useState<string>("");
    let [filter, setFilter] = useState<{
        tcp: boolean;
        udp: boolean;
        icmpv6: boolean;
        icmp: boolean;
        http: boolean,
        tls: boolean,
        ipv4: boolean,
        ipv6: boolean,
        arp: boolean,
        src_ip: boolean
    }>({
        http: true,
        icmp: true,
        icmpv6: true,
        ipv4: true,
        ipv6: true,
        tls: true,
        tcp: true,
        udp: true,
        arp: true,
        src_ip: false
    });

    useEffect(() => {
        const setup = async () => {
            /* Interfaces initialization */
            try {
                const interfaces = await API.getInterfacesList();
                setInterfaces(interfaces);
            } catch (exception) {
                setFeedbackMessage({
                    isError: true,
                    duration: -1,
                    text: "Unable to retrieve interfaces, try running this App as administrator"
                });
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

    const generateReport = async () => {
        try {
            timerStartTime.current = Date.now();
            await API.generateReport(`${reportFolder}${reportFileName}.txt`, firstReportGeneration.current);
            if (firstReportGeneration.current)
                firstReportGeneration.current = false;
            setFeedbackMessage({
                isError: false,
                duration: 5000,
                text: "Report generated"
            });
        } catch (exception) {
            setFeedbackMessage({
                isError: true,
                duration: 8000,
                text: "There was an error trying to generate the report: " + exception
            });
        }
    }

    const updateReportProgress = () => {
        const elapsedTime = Math.floor((Date.now() - timerStartTime.current) / 1000);
        setSecondsToReportGeneration(reportUpdateTime - elapsedTime);
        setReportProgress(Math.ceil(elapsedTime / (reportUpdateTime - 1) * 100));
    }

    const resumeReportGenerationTimer = async () => {
        timerStartTime.current = Date.now();
        setReportGenerationTimer(setInterval(generateReport, reportUpdateTime * 1000));
        await generateReport();
    }

    const selectInterface = async (interfaceName: string) => {
        await API.selectInterface(interfaceName);
        setCurrentInterface(interfaceName);
    }

    const clearTimers = () => {
        if (reportResumeTimeout)
            clearTimeout(reportResumeTimeout);
        if (reportGenerationTimer)
            clearInterval(reportGenerationTimer);
        if (reportProgressTimer)
            clearInterval(reportProgressTimer);
    }

    const stopSniffing = async () => {
        if (sniffingStatus !== SniffingStatus.Active) return;
        setActionLoading("stop");
        clearTimers();
        await API.stopSniffing();
        firstReportGeneration.current = true;
        setSniffingStatus(SniffingStatus.Inactive);
    }

    const startSniffing = async () => {
        if (currentInterface === null || sniffingStatus !== SniffingStatus.Inactive) return;
        setActionLoading("start");
        timerStartTime.current = Date.now();
        setReportGenerationTimer(setInterval(generateReport, reportUpdateTime * 1000));
        setReportProgressTimer(setInterval(updateReportProgress, 500));
        await API.startSniffing();
        setSniffingStatus(SniffingStatus.Active);
    }

    const pauseSniffing = async () => {
        if (sniffingStatus !== SniffingStatus.Active) return;
        setActionLoading("pause");

        clearTimers();
        const elapsedTime = Date.now() - timerStartTime.current;
        setTimerRemainingTime(Math.max(0, reportUpdateTime * 1000 - elapsedTime));

        await API.stopSniffing();
        setSniffingStatus(SniffingStatus.Paused);
    }

    const resumeSniffing = async () => {
        if (currentInterface === null || sniffingStatus !== SniffingStatus.Paused) return;
        setActionLoading("resume");
        timerStartTime.current = Date.now() - (reportUpdateTime * 1000 - timerRemainingTime);
        setReportResumeTimeout(setTimeout(resumeReportGenerationTimer, timerRemainingTime));
        setReportProgressTimer(setInterval(updateReportProgress, 500));
        await API.startSniffing();
        setSniffingStatus(SniffingStatus.Active);
    }

    const startStopSniffing = async () => {
        if (sniffingStatus === SniffingStatus.Inactive) await startSniffing();
        else if (sniffingStatus === SniffingStatus.Active) await stopSniffing();
        setActionLoading("");
    }

    const pauseResumeSniffing = async () => {
        if (sniffingStatus === SniffingStatus.Paused) await resumeSniffing();
        else if (sniffingStatus === SniffingStatus.Active) await pauseSniffing();
        setActionLoading("");
    }

    // TODO: filters (refactor in a new file; check all level types)
    const packetFilter = (packet: GeneralPacket) => {
        let condition = false;

        if (filter.tcp)
            condition = condition || packet.layers.includes("TCP");
        if (filter.udp)
            condition = condition || packet.layers.includes("UDP");
        if (filter.icmp)
            condition = condition || packet.layers.includes("ICMP");
        if (filter.icmpv6)
            condition = condition || packet.layers.includes("ICMPv6");
        if (filter.http)
            condition = condition || packet.layers.includes("HTTP");
        if (filter.tls)
            condition = condition || packet.layers.includes("TLS");
        if (filter.ipv4)
            condition = condition || packet.layers.includes("IPv4");
        if (filter.ipv6)
            condition = condition || packet.layers.includes("IPv6");
        if (filter.src_ip)
            condition = condition || packet.sourceIP === srcIpForm

        return condition;
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
                            <ToggleButton toggleFunction={startStopSniffing}
                                          disabled={currentInterface === "" || actionLoading.length > 0}
                                          loading={actionLoading === "start" || actionLoading === "stop"}
                                          condition={sniffingStatus === SniffingStatus.Active}
                                          textTrue={"Stop Sniffing"} textFalse={"Start Sniffing"}
                                          iconTrue={<Stop/>} iconFalse={<PlayArrow/>}
                            />
                        }
                        {
                            sniffingStatus !== SniffingStatus.Inactive &&
                            <ToggleButton toggleFunction={pauseResumeSniffing}
                                          disabled={currentInterface === "" || actionLoading.length > 0}
                                          loading={actionLoading === "pause" || actionLoading === "resume"}
                                          condition={sniffingStatus === SniffingStatus.Active}
                                          textTrue={"Pause Sniffing"} textFalse={"Resume Sniffing"}
                                          iconTrue={<Pause/>} iconFalse={<RestartAlt/>}
                            />
                        }
                    </FormControl>
                </Grid>


                {/* Report generation Status */

                    sniffingStatus !== SniffingStatus.Inactive && <Grid xs={12} item={true}>
                        Next report generated in: {secondsToReportGeneration}s
                        <LinearProgress variant="determinate" value={reportProgress}/>
                    </Grid>
                }

                {/* Filter */}
                <Grid xs={12} item={true} className={"container-center"}>
                    <Accordion>
                        <AccordionSummary expandIcon={<ExpandMoreIcon/>}>Filters</AccordionSummary>
                        <AccordionDetails>
                            <Box sx={{display: 'flex'}}>
                                <FormControl sx={{m: 3}} component="fieldset" variant="standard">
                                    <FormLabel component="legend">Network Layer</FormLabel>
                                    <FormGroup>
                                        <FormControlLabel
                                            control={
                                                <Checkbox checked={filter.ipv6} onChange={(ev) => {
                                                    if (ev.target.checked)
                                                        setFilter((f) => Object.assign({}, f, {ipv6: true}));
                                                    else
                                                        setFilter((f) => Object.assign({}, f, {ipv6: false}));
                                                }} name="ipv6"/>
                                            }
                                            label="IPv6"
                                        />
                                        <FormControlLabel
                                            control={
                                                <Checkbox checked={filter.ipv4} onChange={(ev) => {
                                                    if (ev.target.checked)
                                                        setFilter((f) => Object.assign({}, f, {ipv4: true}));
                                                    else
                                                        setFilter((f) => Object.assign({}, f, {ipv4: false}));
                                                }} name="ipv4"/>
                                            }
                                            label="IPv4"
                                        />
                                        <FormControlLabel
                                            control={
                                                <Checkbox checked={filter.arp} onChange={(ev) => {
                                                    if (ev.target.checked)
                                                        setFilter((f) => Object.assign({}, f, {arp: true}));
                                                    else
                                                        setFilter((f) => Object.assign({}, f, {arp: false}));
                                                }} name="arp"/>
                                            }
                                            label="ARP"
                                        />
                                    </FormGroup>
                                </FormControl>
                                <FormControl sx={{m: 3}} component="fieldset" variant="standard">
                                    <FormLabel component="legend">Transport Layer</FormLabel>
                                    <FormGroup>
                                        <FormControlLabel
                                            control={
                                                <Checkbox checked={filter.tcp} onChange={(ev) => {
                                                    if (ev.target.checked)
                                                        setFilter((f) => Object.assign({}, f, {tcp: true}));
                                                    else
                                                        setFilter((f) => Object.assign({}, f, {tcp: false}));
                                                }} name="tcp"/>
                                            }
                                            label="TCP"
                                        />
                                        <FormControlLabel
                                            control={
                                                <Checkbox checked={filter.udp} onChange={(ev) => {
                                                    if (ev.target.checked)
                                                        setFilter((f) => Object.assign({}, f, {udp: true}));
                                                    else
                                                        setFilter((f) => Object.assign({}, f, {udp: false}));
                                                }} name="udp"/>
                                            }
                                            label="UDP"
                                        />
                                        <FormControlLabel
                                            control={
                                                <Checkbox checked={filter.icmpv6} onChange={(ev) => {
                                                    if (ev.target.checked)
                                                        setFilter((f) => Object.assign({}, f, {icmpv6: true}));
                                                    else
                                                        setFilter((f) => Object.assign({}, f, {icmpv6: false}));
                                                }} name="icmpv6"/>
                                            }
                                            label="ICMPv6"
                                        />
                                        <FormControlLabel
                                            control={
                                                <Checkbox checked={filter.icmp} onChange={(ev) => {
                                                    if (ev.target.checked)
                                                        setFilter((f) => Object.assign({}, f, {icmp: true}));
                                                    else
                                                        setFilter((f) => Object.assign({}, f, {icmp: false}));
                                                }} name="icmp"/>
                                            }
                                            label="ICMP"
                                        />
                                    </FormGroup>
                                </FormControl>
                                <FormControl sx={{m: 3}} component="fieldset" variant="standard">
                                    <FormLabel component="legend">Application Layer</FormLabel>
                                    <FormGroup>
                                        <FormControlLabel
                                            control={
                                                <Checkbox checked={filter.http} onChange={(ev) => {
                                                    if (ev.target.checked)
                                                        setFilter((f) => Object.assign({}, f, {http: true}));
                                                    else
                                                        setFilter((f) => Object.assign({}, f, {http: false}));
                                                }} name="http"/>
                                            }
                                            label="HTTP"
                                        />
                                        <FormControlLabel
                                            control={
                                                <Checkbox checked={filter.tls} onChange={(ev) => {
                                                    if (ev.target.checked)
                                                        setFilter((f) => Object.assign({}, f, {tls: true}));
                                                    else
                                                        setFilter((f) => Object.assign({}, f, {tls: false}));
                                                }} name="tls"/>
                                            }
                                            label="TLS"
                                        />
                                    </FormGroup>
                                </FormControl>
                                <FormControl sx={{m: 3}} component="fieldset" variant="standard">
                                    <FormLabel component="legend">Others</FormLabel>
                                    <FormControlLabel
                                        control={
                                            <>
                                                <Checkbox checked={filter.src_ip} onChange={(ev) => {
                                                    if (ev.target.checked)
                                                        setFilter((f) => Object.assign({}, f, {src_ip: true}));
                                                    else
                                                        setFilter((f) => Object.assign({}, f, {src_ip: false}));
                                                }} name="src_ip"/>
                                                <TextField
                                                    onChange={(s) => setSrcIpForm(s.target.value)}
                                                    disabled={!filter.src_ip} id="src_ip" label="SOURCE IP" variant="standard"/>
                                            </>
                                        }
                                        label=""
                                    />
                                    <FormGroup>
                                    </FormGroup>
                                </FormControl>
                            </Box>
                        </AccordionDetails>
                    </Accordion>
                </Grid>


                {/* Sniffing Results */}

                <Grid xs={12} item={true}>
                    <DataGrid style={{marginTop: "15px", minHeight: "250px"}}
                              rows={capturedPackets.filter(packetFilter)} columns={columns}
                              onCellClick={(ev) => setSelectedPacket(ev.row)}/>
                </Grid>

                <Snackbar anchorOrigin={{vertical: "bottom", horizontal: "right"}}
                          open={feedbackMessage.text.length > 0}
                          key={feedbackMessage.text}
                          autoHideDuration={feedbackMessage.duration}
                          message={feedbackMessage.text}
                          onClick={() => setFeedbackMessage(resetFeedback)}
                          onClose={(event: React.SyntheticEvent | Event, reason?: string) => {
                              if (reason === 'clickaway') return;
                              setFeedbackMessage(resetFeedback);
                          }}
                >
                    <Alert severity={feedbackMessage.isError ? 'error' : 'success'}>
                        {feedbackMessage.text}
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
    )
        ;

}

export default App;
