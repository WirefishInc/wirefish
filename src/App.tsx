import {ThemeProvider, createTheme} from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import {useState, useEffect, FC} from 'react';
import {
    Accordion, AccordionDetails, AccordionSummary, Alert, Divider, Fab, FormControl, Grid, List, ListItem, Paper,
    Snackbar, Stack, styled
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
import {EthernetPacket} from "./serializable_packet/link";
import {ArpPacket, Ipv4Packet, Ipv6Packet} from "./serializable_packet/network";
import {TcpPacket, UdpPacket, Icmpv6Packet, IcmpPacket, EchoReply, EchoRequest} from "./serializable_packet/transport";
import {
    Packet, SniffingStatus, SerializableNetworkLayerPacket,
    SerializableTransportLayerPacket, SerializableLinkLayerPacket
} from "./types/sniffing";

// TODO IMPORTANT !!! ALL PACKETS IN TABLE DUPLICATED

const darkTheme = createTheme({
    palette: {
        mode: 'dark',
    },
});

const columns: GridColDef[] = [
    {field: 'id', headerName: '#', width: 10},
    {field: 'type', headerName: 'Type', width: 140, valueGetter: p => p.row.link_layer_packet.ethertype}, // TODO
    {field: 'sourceMAC', headerName: 'Source MAC', width: 140, valueGetter: p => p.row.link_layer_packet.source},
    {
        field: 'destinationMAC',
        headerName: 'Destination MAC',
        width: 140,
        valueGetter: p => p.row.link_layer_packet.destination
    },
    {field: 'sourceIP', headerName: 'Source IP', width: 120, valueGetter: p => p.row.network_layer_packet.source},
    {
        field: 'destinationIP',
        headerName: 'Destination IP',
        width: 120,
        valueGetter: p => p.row.network_layer_packet.destination
    },
    {field: 'length', headerName: 'Lenght', width: 100, valueGetter: p => p.row.link_layer_packet.payload.length}, // TODO
    {field: 'info', headerName: 'Info', width: 200, valueGetter: p => "info"}, // TODO
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
    let [selectedPacket, setSelectedPacket] = useState<Packet | null>(null);

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
                let link_layer: SerializableLinkLayerPacket | null;
                let network_layer: SerializableNetworkLayerPacket | null;
                let transport_layer: SerializableTransportLayerPacket | null;

                if (packet.linkLayerPacket)
                    link_layer = make_link_level_packet(packet.linkLayerPacket);

                if (packet.networkLayerPacket)
                    network_layer = make_network_level_packet(packet.networkLayerPacket);

                if (packet.transportLayerPacket)
                    transport_layer = make_transport_level_packet(packet.transportLayerPacket);

                setCapturedPackets(packets => {
                    return [...packets, new Packet(packets.length, link_layer, network_layer, transport_layer)];
                });
            });
        };

        setup();
    }, []);

    const make_link_level_packet = (link: any) => {
        let link_layer: SerializableLinkLayerPacket | null = null;

        switch (link.type) {
            case "EthernetPacket":
                //link_layer = link.packet as EthernetPacket;
                link_layer = new EthernetPacket(
                    link.packet.destination,
                    link.packet.source,
                    link.packet.ethertype,
                    link.packet.payload
                )
                break;

            default:
                console.log("Malformed packet") // TODO
        }

        return link_layer;
    }

    const make_network_level_packet = (network: any) => {
        let network_layer: SerializableNetworkLayerPacket | null = null;

        // TODO REFACTOR CONSTRUCTOR

        switch (network.type) {
            case "ArpPacket":
                //network_layer = network.packet as ArpPacket;
                network_layer = new ArpPacket(
                    network.packet.hardware_type,
                    network.packet.protocol_type,
                    network.packet.hw_addr_len,
                    network.packet.proto_addr_len,
                    network.packet.operation,
                    network.packet.sender_hw_addr,
                    network.packet.sender_proto_addr,
                    network.packet.target_hw_addr,
                    network.packet.target_proto_addr,
                    network.packet.payload
                )
                break;

            case "Ipv4Packet":
                //network_layer = network.packet as Ipv4Packet;
                network_layer = new Ipv4Packet(
                    network.packet.version,
                    network.packet.header_length,
                    network.packet.dscp,
                    network.packet.ecn,
                    network.packet.total_length,
                    network.packet.identification,
                    network.packet.flags,
                    network.packet.fragment_offset,
                    network.packet.ttl,
                    network.packet.next_level_protocol,
                    network.packet.checksum,
                    network.packet.source,
                    network.packet.destination,
                    network.packet.payload
                )
                break;

            case "Ipv6Packet":
                //network_layer = network.packet as Ipv6Packet;
                network_layer = new Ipv6Packet(
                    network.packet.version,
                    network.packet.traffic_class,
                    network.packet.flow_label,
                    network.packet.payload_length,
                    network.packet.next_header,
                    network.packet.hop_limit,
                    network.packet.source,
                    network.packet.destination,
                    network.packet.payload
                )
                break;

            default:
                console.log("Malformed packet") // TODO
        }

        return network_layer;
    }

    const make_transport_level_packet = (transport: any) => {
        let transport_layer: SerializableTransportLayerPacket | null = null

        switch (transport.type) {
            case "TcpPacket":
                //transport_layer = transport.packet as TcpPacket;
                transport_layer = new TcpPacket(
                    transport.packet.source,
                    transport.packet.destination,
                    transport.packet.sequence,
                    transport.packet.acknowledgement,
                    transport.packet.data_offset,
                    transport.packet.reserved,
                    transport.packet.flags,
                    transport.packet.window,
                    transport.packet.checksum,
                    transport.packet.urgent_ptr,
                    transport.packet.options,
                    transport.packet.payload
                )
                break;

            case "UdpPacket":
                //transport_layer = transport.packet as UdpPacket;
                transport_layer = new UdpPacket(
                    transport.packet.source,
                    transport.packet.destination,
                    transport.packet.length,
                    transport.packet.checksum,
                    transport.packet.payload
                )
                break;

            case "Icmpv6Packet":
                //transport_layer = transport.packet as Icmpv6Packet;
                transport_layer = new Icmpv6Packet(
                    transport.packet.icmpv6_type,
                    transport.packet.icmpv6_code,
                    transport.packet.checksum,
                    transport.packet.payload
                )
                break;

            case "IcmpPacket":
                //transport_layer = transport.packet as IcmpPacket;
                transport_layer = new IcmpPacket(
                    transport.packet.icmp_type,
                    transport.packet.icmp_code,
                    transport.packet.checksum,
                    transport.packet.payload
                )
                break;

            case "EchoReplyPacket":
                //transport_layer = transport.packet as EchoReply;
                transport_layer = new EchoReply(
                    transport.packet.icmp_type,
                    transport.packet.icmp_code,
                    transport.packet.checksum,
                    transport.packet.identifier,
                    transport.packet.sequence_number,
                    transport.packet.payload
                )
                break;

            case "EchoRequestPacket":
                //transport_layer = transport.packet as EchoRequest;
                transport_layer = new EchoRequest(
                    transport.packet.icmp_type,
                    transport.packet.icmp_code,
                    transport.packet.checksum,
                    transport.packet.identifier,
                    transport.packet.sequence_number,
                    transport.packet.payload
                )
                break;

            default:
                console.log("Malformed packet") // TODO
        }

        return transport_layer;
    }

    const selectInterface = async (interfaceName: string) => {
        await API.selectInterface(interfaceName);
        setCurrentInterface(interfaceName);
    }

    const stopSniffing = async () => {
        await API.stopSniffing();
        setSniffingStatus(SniffingStatus.Inactive);
        console.log(capturedPackets) // TODO: delete
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
                                {!selectedPacket.link_layer_packet ? null :
                                    <Accordion>
                                        <AccordionSummary expandIcon={<ExpandMoreIcon/>}>
                                            {selectedPacket.link_layer_packet?.toString()}
                                        </AccordionSummary>
                                        <AccordionDetails>
                                            <List component="nav" aria-label="mailbox folders">
                                                <Fields packetInfo={selectedPacket.link_layer_packet.toDisplay()}/>
                                            </List>
                                        </AccordionDetails>
                                    </Accordion>
                                }
                                {!selectedPacket.network_layer_packet ? null :
                                    <Accordion>
                                        <AccordionSummary expandIcon={<ExpandMoreIcon/>}>
                                            {selectedPacket.network_layer_packet?.toString()}
                                        </AccordionSummary>
                                        <AccordionDetails>
                                            <List component="nav" aria-label="mailbox folders">
                                                <Fields packetInfo={selectedPacket.network_layer_packet.toDisplay()}/>
                                            </List>
                                        </AccordionDetails>
                                    </Accordion>
                                }
                                {!selectedPacket.transport_layer_packet ? null :
                                    <Accordion>
                                        <AccordionSummary expandIcon={<ExpandMoreIcon/>}>
                                            {selectedPacket.transport_layer_packet?.toString()}
                                        </AccordionSummary>
                                        <AccordionDetails>
                                            <List component="nav" aria-label="mailbox folders">
                                                <Fields packetInfo={selectedPacket.transport_layer_packet.toDisplay()}/>
                                            </List>
                                        </AccordionDetails>
                                    </Accordion>
                                }
                            </Grid>
                        </>
                }
            </Grid>
        </ThemeProvider>
    );
}

export default App;
