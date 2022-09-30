import {createTheme, ThemeProvider} from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import React, {useState, useEffect, useRef} from 'react';
import {
    Accordion,
    AccordionDetails,
    AccordionSummary,
    Alert, Chip,
    FormControl,
    Grid,
    LinearProgress,
    List,
    Modal,
    Snackbar,
} from '@mui/material';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import {Pause, PlayArrow, RestartAlt, Stop} from '@mui/icons-material';
import {DataGrid, GridColDef} from '@mui/x-data-grid';
import './index.css';
import API from './API';
import {SniffingStatus, GeneralPacket, FeedbackMessage} from "./types/sniffing";
import InterfaceInput from './components/InterfaceInput';
import TimeIntervalInput from './components/TimeIntervalInput';
import ReportFolderInput from "./components/ReportFolderInput";
import ReportNameInput from "./components/ReportNameInput";
import ToggleButton from "./components/ToggleButton";
import {DnsFields, Fields, TlsFields} from "./components/Fields";
import HewViewer from "./components/HexViewer";
import Filters from "./components/Filters";

const darkTheme = createTheme({
    palette: {
        mode: 'dark',
    },
});

const columns: GridColDef[] = [
    {field: 'id', headerName: '#', width: 70, disableColumnMenu: true, sortable: false},
    {
        field: 'type',
        headerName: 'Last Type',
        width: 100,
        valueGetter: p => p.row.type,
        disableColumnMenu: true,
        sortable: false
    },
    {
        field: 'sourceMAC',
        headerName: 'Source MAC',
        width: 150,
        valueGetter: p => p.row.sourceMAC,
        disableColumnMenu: true,
        sortable: false
    },
    {
        field: 'destinationMAC',
        headerName: 'Destination MAC',
        width: 150,
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
        width: 420,
        valueGetter: p => p.row.info,
        disableColumnMenu: true,
        sortable: false
    },
];

function App() {

    const REPORT_GENERATION_SECONDS = 30;
    const INITIAL_REPORT_NAME = "report";
    const resetFeedback = {text: "", isError: false, duration: 0};
    const [open, setOpen] = React.useState(false);
    const handleOpen = () => setOpen(true);
    const handleClose = () => setOpen(false);

    let [interfaces, setInterfaces] = useState<string[] | null>(null);
    let [currentInterface, setCurrentInterface] = useState<string>("");
    let [sniffingStatus, setSniffingStatus] = useState<SniffingStatus>(SniffingStatus.Inactive);
    let [capturedPackets, setCapturedPackets] = useState<GeneralPacket[]>([]);
    let [reportUpdateTime, setReportUpdateTime] = useState<number>(REPORT_GENERATION_SECONDS);
    let [reportFileName, setReportFileName] = useState<string>(INITIAL_REPORT_NAME);
    let [reportFolder, setReportFolder] = useState<string>("");
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
    let [filterEnabled, setFilterEnabled] = useState<boolean>(false);
    let [srcIpForm, setSrcIpForm] = useState<string>("");
    let [dstIpForm, setDstIpForm] = useState<string>("");
    let [srcMacForm, setSrcMacForm] = useState<string>("");
    let [dstMacForm, setDstMacForm] = useState<string>("");
    let [srcPortForm, setSrcPortForm] = useState<string>("");
    let [dstPortForm, setDstPortForm] = useState<string>("");
    let [infoForm, setInfoForm] = useState<string>("");
    let [inputValidated, setInputValidated] = useState<boolean>(false);

    let [filter, setFilter] = useState<{
        ethernet: boolean,
        malformed: boolean,
        unknown: boolean,
        tcp: boolean;
        udp: boolean;
        icmpv6: boolean;
        icmp: boolean;
        http: boolean,
        tls: boolean,
        ipv4: boolean,
        ipv6: boolean,
        arp: boolean,
        dns: boolean,
        src_ip: boolean,
        dst_ip: boolean,
        src_mac: boolean,
        dst_mac: boolean,
        src_port: boolean,
        dst_port: boolean,
        info: boolean
    }>({
        ethernet: false,
        malformed: false,
        unknown: false,
        http: false,
        icmp: false,
        icmpv6: false,
        ipv4: false,
        ipv6: false,
        tls: false,
        tcp: false,
        udp: false,
        arp: false,
        dns: false,
        src_ip: false,
        dst_ip: false,
        src_mac: false,
        dst_mac: false,
        src_port: false,
        dst_port: false,
        info: false
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
                    duration: 8000,
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
            await API.generateReport(`${reportFolder}${reportFileName}.csv`, firstReportGeneration.current);
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
        try {
            await API.selectInterface(interfaceName);
            setCurrentInterface(interfaceName);
        } catch (e: any) {
            setFeedbackMessage({
                isError: true,
                duration: 8000,
                text: e.error
            });
        }
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

        try {
            await API.stopSniffing(true);
            setActionLoading("stop");
            clearTimers();
            firstReportGeneration.current = true;
            setSniffingStatus(SniffingStatus.Inactive);

        } catch (e: any) {
            setFeedbackMessage({
                isError: true,
                duration: 8000,
                text: e.error
            });
        }
    }

    const startSniffing = async () => {
        if (currentInterface === "" || !reportFolder || sniffingStatus !== SniffingStatus.Inactive) return;

        try {
            await API.startSniffing();

            setActionLoading("start");
            timerStartTime.current = Date.now();
            setReportGenerationTimer(setInterval(generateReport, reportUpdateTime * 1000));
            setReportProgressTimer(setInterval(updateReportProgress, 500));
            setSniffingStatus(SniffingStatus.Active);

        } catch (e: any) {
            setFeedbackMessage({
                isError: true,
                duration: 8000,
                text: e.error
            });
        }

    }

    const pauseSniffing = async () => {
        if (sniffingStatus !== SniffingStatus.Active) return;

        try {
            await API.stopSniffing(false);

            setActionLoading("pause");

            clearTimers();
            const elapsedTime = Date.now() - timerStartTime.current;
            setTimerRemainingTime(Math.max(0, reportUpdateTime * 1000 - elapsedTime));

            setSniffingStatus(SniffingStatus.Paused);
        } catch (e: any) {
            setFeedbackMessage({
                isError: true,
                duration: 8000,
                text: e.error
            });
        }

    }

    const resumeSniffing = async () => {
        if (currentInterface === "" || !reportFolder || sniffingStatus !== SniffingStatus.Paused) return;

        try {
            await API.startSniffing();

            setActionLoading("resume");
            timerStartTime.current = Date.now() - (reportUpdateTime * 1000 - timerRemainingTime);
            setReportResumeTimeout(setTimeout(resumeReportGenerationTimer, timerRemainingTime));
            setReportProgressTimer(setInterval(updateReportProgress, 500));

            setSniffingStatus(SniffingStatus.Active);
        } catch (e: any) {
            setFeedbackMessage({
                isError: true,
                duration: 8000,
                text: e.error
            });
        }
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

    const packetFilter = (packet: GeneralPacket) => {
        let condition = !filterEnabled;

        if (filterEnabled) {
            if (filter.unknown)
                condition = condition || packet.layers.includes("Unknown");
            if (filter.malformed)
                condition = condition || packet.layers.includes("Malformed");
            if (filter.ethernet)
                condition = condition || packet.layers.includes("Ethernet");
            if (filter.tcp)
                condition = condition || packet.layers.includes("TCP");
            if (filter.udp)
                condition = condition || packet.layers.includes("UDP");
            if (filter.icmp)
                condition = condition || packet.layers.includes("ICMP")
                    || packet.layers.includes("Echo Reply") || packet.layers.includes("Echo Request");
            if (filter.icmpv6)
                condition = condition || packet.layers.includes("ICMPv6")
                    || packet.layers.includes("Echo Reply") || packet.layers.includes("Echo Request");
            if (filter.http)
                condition = condition || packet.layers.includes("HTTP");
            if (filter.tls)
                condition = condition || packet.layers.includes("TLS");
            if (filter.ipv4)
                condition = condition || packet.layers.includes("IPv4");
            if (filter.ipv6)
                condition = condition || packet.layers.includes("IPv6");
            if (filter.dns)
                condition = condition || packet.layers.includes("DNS");
            if (filter.arp)
                condition = condition || packet.layers.includes("ARP");
            if (filter.src_ip)
                condition = condition || packet.sourceIP === srcIpForm
            if (filter.dst_ip)
                condition = condition || packet.destinationIP === dstIpForm
            if (filter.src_mac)
                condition = condition || packet.sourceMAC === srcMacForm
            if (filter.dst_mac)
                condition = condition || packet.destinationMAC === dstMacForm
            if (filter.src_port)
                condition = condition || (packet.sourcePort !== null && packet.sourcePort.toString() === srcPortForm)
            if (filter.dst_port)
                condition = condition || (packet.destinationPort !== null && packet.destinationPort.toString() === dstPortForm)
            if (filter.info)
                condition = condition || packet.info.toLowerCase().includes(infoForm.toLowerCase())
        }

        return condition;
    }

    return (
        <ThemeProvider theme={darkTheme}>
            <CssBaseline/>
            <Grid container spacing={2} className={open ? "container-main blur" : "container-main"}>

                {/* Interface selection */}

                <Grid xs={12} item={true}>
                    <InterfaceInput currentInterface={currentInterface} selectInterface={selectInterface}
                                    validated={inputValidated} interfaces={interfaces} sniffingStatus={sniffingStatus}/>
                </Grid>

                {/* Time interval selection */}

                <Grid xs={3} item={true}>
                    <TimeIntervalInput reportUpdateTime={reportUpdateTime} sniffingStatus={sniffingStatus}
                                       setReportUpdateTime={setReportUpdateTime}/>
                </Grid>

                {/* Output file selection */}

                <Grid xs={6} item={true}>
                    <ReportFolderInput setReportFolder={setReportFolder} sniffingStatus={sniffingStatus}
                                       reportFolder={reportFolder} validated={inputValidated}/>
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
                            <ToggleButton toggleFunction={startStopSniffing} setInputValidated={setInputValidated}
                                          disabled={currentInterface === "" || !reportFolder || actionLoading.length > 0}
                                          loading={actionLoading === "start" || actionLoading === "stop"}
                                          condition={sniffingStatus === SniffingStatus.Active}
                                          textTrue={"Stop Sniffing"} textFalse={"Start Sniffing"}
                                          iconTrue={<Stop/>} iconFalse={<PlayArrow/>}
                            />
                        }
                        {
                            sniffingStatus !== SniffingStatus.Inactive &&
                            <ToggleButton toggleFunction={pauseResumeSniffing} setInputValidated={null}
                                          disabled={currentInterface === "" || !reportFolder || actionLoading.length > 0}
                                          loading={actionLoading === "pause" || actionLoading === "resume"}
                                          condition={sniffingStatus === SniffingStatus.Active}
                                          textTrue={"Pause Sniffing"} textFalse={"Resume Sniffing"}
                                          iconTrue={<Pause/>} iconFalse={<RestartAlt/>}
                            />
                        }
                    </FormControl>
                </Grid>


                {/* Report generation Status */}

                {
                    sniffingStatus !== SniffingStatus.Inactive && <Grid xs={12} item={true}>
                        Next report generated in: {secondsToReportGeneration}s
                        <LinearProgress variant="determinate" value={reportProgress}/>
                    </Grid>
                }

                {/* Filters */}

                <Filters filter={filter} setFilter={setFilter}
                         setSrcIpForm={setSrcIpForm} setDstIpForm={setDstIpForm}
                         setSrcMacForm={setSrcMacForm} setDstMacForm={setDstMacForm}
                         setSrcPortForm={setSrcPortForm} setDstPortForm={setDstPortForm}
                         setInfoForm={setInfoForm} enabled={filterEnabled} setEnabled={setFilterEnabled}/>

                {/* Sniffing Results */}

                <Grid xs={12} item={true}>
                    <DataGrid className={"grid"}
                              rows={capturedPackets.filter(packetFilter)} rowHeight={40} columns={columns}
                              onCellClick={(ev) => {
                                  setSelectedPacket(ev.row)
                                  handleOpen();
                              }}
                    />
                </Grid>

                {/* Report result feedback */}

                <Snackbar anchorOrigin={{vertical: "bottom", horizontal: "right"}}
                          open={feedbackMessage.text.length > 0}
                          key={feedbackMessage.text}
                          autoHideDuration={feedbackMessage.duration}
                          message={feedbackMessage.text}
                          onClick={() => setFeedbackMessage(resetFeedback)}
                          onClose={(event: React.SyntheticEvent | Event, reason?: string) => {
                              if (reason === 'clickaway') return;
                              setFeedbackMessage(resetFeedback);
                          }}>
                    <Alert severity={feedbackMessage.isError ? 'error' : 'success'}>
                        {feedbackMessage.text}
                    </Alert>
                </Snackbar>

                {/* Packet Info Viewer */}

                <Modal
                    className={"modal"}
                    open={open}
                    onClose={handleClose}
                >

                    <>
                        <Grid className={"title"}>
                            <Chip size={"medium"} className={"chip"} variant="outlined"
                                  label={"Selected Packet Layers"}/>
                        </Grid>

                        <Grid container spacing={2} className={"container-main"}>

                            {/* Info selected Packet */}

                            {
                                !selectedPacket ? null :
                                    <>

                                        <Grid xs={12} item={true}>

                                            {/* Link Layer */}

                                            <Accordion>
                                                <AccordionSummary expandIcon={<ExpandMoreIcon/>}>
                                                    {selectedPacket.packet.link_layer_packet.toString()}
                                                </AccordionSummary>
                                                <AccordionDetails>
                                                    <List component="nav" aria-label="mailbox folders">
                                                        <Fields
                                                            packetInfo={selectedPacket.packet.link_layer_packet.toDisplay()}/>
                                                    </List>
                                                </AccordionDetails>
                                            </Accordion>

                                            {/* Network Layer */}

                                            {!selectedPacket.packet.network_layer_packet ? null :
                                                <Accordion>
                                                    <AccordionSummary expandIcon={<ExpandMoreIcon/>}>
                                                        {selectedPacket.packet.network_layer_packet.toString()}
                                                    </AccordionSummary>
                                                    <AccordionDetails>
                                                        <List component="nav" aria-label="mailbox folders">
                                                            <Fields
                                                                packetInfo={selectedPacket.packet.network_layer_packet.toDisplay()}/>
                                                        </List>
                                                    </AccordionDetails>
                                                </Accordion>
                                            }

                                            {/* Transport Layer */}

                                            {!selectedPacket.packet.transport_layer_packet ? null :
                                                <Accordion>
                                                    <AccordionSummary expandIcon={<ExpandMoreIcon/>}>
                                                        {selectedPacket.packet.transport_layer_packet.toString()}
                                                    </AccordionSummary>
                                                    <AccordionDetails>
                                                        <List component="nav" aria-label="mailbox folders">
                                                            <Fields
                                                                packetInfo={selectedPacket.packet.transport_layer_packet.toDisplay()}/>
                                                        </List>
                                                    </AccordionDetails>
                                                </Accordion>
                                            }

                                            {/* Application Layer */}

                                            {!selectedPacket.packet.application_layer_packet ? null :
                                                <Accordion>
                                                    <AccordionSummary expandIcon={<ExpandMoreIcon/>}>
                                                        {selectedPacket.packet.application_layer_packet.toString()}
                                                    </AccordionSummary>
                                                    <AccordionDetails>
                                                        <List component="nav" aria-label="mailbox folders">
                                                            {
                                                                selectedPacket.packet.application_layer_packet.getType() === "TLS" ?
                                                                    <TlsFields
                                                                        packetInfo={selectedPacket.packet.application_layer_packet.toDisplay()}/>
                                                                    :
                                                                    selectedPacket.packet.application_layer_packet.getType() === "DNS" ?
                                                                        <DnsFields
                                                                            packetInfo={selectedPacket.packet.application_layer_packet.toDisplay()}/>
                                                                        :
                                                                        <Fields
                                                                            packetInfo={selectedPacket.packet.application_layer_packet.toDisplay()}/>
                                                            }
                                                        </List>
                                                    </AccordionDetails>
                                                </Accordion>
                                            }

                                        </Grid>
                                    </>
                            }
                        </Grid>

                        {/* Payload (hex viewer) */}

                        <Grid className={"title"}>
                            <Chip size={"medium"} className={"chip"} variant="outlined"
                                  label={"Selected Packet Payload Viewer"}/>
                        </Grid>

                        {!selectedPacket ? null :
                            <HewViewer
                                over={over}
                                setOver={setOver}
                                payload={selectedPacket.packet.link_layer_packet.getPayload()}/>
                        }
                    </>
                </Modal>

            </Grid>
        </ThemeProvider>
    );
}

export default App;
