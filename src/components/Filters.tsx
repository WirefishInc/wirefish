import React, {FC} from "react";
import {
    Accordion,
    AccordionDetails,
    AccordionSummary, Checkbox,
    FormControl,
    FormControlLabel,
    FormGroup,
    FormLabel, Grid, Switch, TextField
} from "@mui/material";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import Box from "@mui/material/Box";
import {ArrowDropDownCircleTwoTone, FilterAlt, FilterList} from "@mui/icons-material";


interface FiltersProps {
    enabled: boolean,
    setEnabled: any,
    filter: any,
    setFilter: any,
    setSrcIpForm: any,
    setDstIpForm: any,
    setSrcMacForm: any,
    setDstMacForm: any,
    setSrcPortForm: any,
    setDstPortForm: any,
    setInfoForm: any
}

const Filters: FC<FiltersProps> = ({
                                       enabled,
                                       setEnabled,
                                       filter,
                                       setFilter,
                                       setDstIpForm,
                                       setDstMacForm,
                                       setDstPortForm,
                                       setSrcMacForm,
                                       setSrcPortForm,
                                       setSrcIpForm,
                                       setInfoForm
                                   }) => {

    return (
        <Grid xs={12} item={true} className={"container-center"}>
            <Accordion>
                <AccordionSummary className={"center"} expandIcon={<FilterList/>}>Filters
                </AccordionSummary>
                <AccordionDetails>
                    <Grid className={"container-center"}>
                        <FormGroup>
                            <FormControlLabel control={<Switch checked={enabled}/>}
                                              label={enabled ? "Disable Filters" : "Enable Filters"}
                                              onChange={(event:any) => setEnabled(event.target.checked)}/>
                        </FormGroup>
                    </Grid>
                    <Box sx={{display: 'flex'}}>
                        <FormControl sx={{m: 3}} component="fieldset" variant="standard">
                            <FormLabel component="legend">Link Layer</FormLabel>
                            <FormGroup>
                                <FormControlLabel
                                    control={
                                        <Checkbox disabled={!enabled} checked={filter.ethernet} onChange={(ev) => {
                                            if (ev.target.checked)
                                                setFilter((f: any) => Object.assign({}, f, {ethernet: true}));
                                            else
                                                setFilter((f: any) => Object.assign({}, f, {ethernet: false}));
                                        }} name="ethernet"/>
                                    }
                                    label="Ethernet"
                                />
                                <FormControlLabel
                                    control={
                                        <Checkbox disabled={!enabled} checked={filter.unknown} onChange={(ev) => {
                                            if (ev.target.checked)
                                                setFilter((f: any) => Object.assign({}, f, {unknown: true}));
                                            else
                                                setFilter((f: any) => Object.assign({}, f, {unknown: false}));
                                        }} name="unknown"/>
                                    }
                                    label="Unknown"
                                />
                                <FormLabel component="legend">Other Packets</FormLabel>
                                <FormControlLabel
                                    control={
                                        <Checkbox disabled={!enabled} checked={filter.malformed} onChange={(ev) => {
                                            if (ev.target.checked)
                                                setFilter((f: any) => Object.assign({}, f, {malformed: true}));
                                            else
                                                setFilter((f: any) => Object.assign({}, f, {malformed: false}));
                                        }} name="malformed"/>
                                    }
                                    label="Malformed"
                                />
                            </FormGroup>
                        </FormControl>
                        <FormControl sx={{m: 3}} component="fieldset" variant="standard">
                            <FormLabel component="legend">Network Layer</FormLabel>
                            <FormGroup>
                                <FormControlLabel
                                    control={
                                        <Checkbox disabled={!enabled} checked={filter.ipv6} onChange={(ev) => {
                                            if (ev.target.checked)
                                                setFilter((f: any) => Object.assign({}, f, {ipv6: true}));
                                            else
                                                setFilter((f: any) => Object.assign({}, f, {ipv6: false}));
                                        }} name="ipv6"/>
                                    }
                                    label="IPv6"
                                />
                                <FormControlLabel
                                    control={
                                        <Checkbox disabled={!enabled} checked={filter.ipv4} onChange={(ev) => {
                                            if (ev.target.checked)
                                                setFilter((f: any) => Object.assign({}, f, {ipv4: true}));
                                            else
                                                setFilter((f: any) => Object.assign({}, f, {ipv4: false}));
                                        }} name="ipv4"/>
                                    }
                                    label="IPv4"
                                />
                                <FormControlLabel
                                    control={
                                        <Checkbox disabled={!enabled} checked={filter.arp} onChange={(ev) => {
                                            if (ev.target.checked)
                                                setFilter((f: any) => Object.assign({}, f, {arp: true}));
                                            else
                                                setFilter((f: any) => Object.assign({}, f, {arp: false}));
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
                                        <Checkbox disabled={!enabled} checked={filter.tcp} onChange={(ev) => {
                                            if (ev.target.checked)
                                                setFilter((f: any) => Object.assign({}, f, {tcp: true}));
                                            else
                                                setFilter((f: any) => Object.assign({}, f, {tcp: false}));
                                        }} name="tcp"/>
                                    }
                                    label="TCP"
                                />
                                <FormControlLabel
                                    control={
                                        <Checkbox disabled={!enabled} checked={filter.udp} onChange={(ev) => {
                                            if (ev.target.checked)
                                                setFilter((f: any) => Object.assign({}, f, {udp: true}));
                                            else
                                                setFilter((f: any) => Object.assign({}, f, {udp: false}));
                                        }} name="udp"/>
                                    }
                                    label="UDP"
                                />
                                <FormControlLabel
                                    control={
                                        <Checkbox disabled={!enabled} checked={filter.icmpv6} onChange={(ev) => {
                                            if (ev.target.checked)
                                                setFilter((f: any) => Object.assign({}, f, {icmpv6: true}));
                                            else
                                                setFilter((f: any) => Object.assign({}, f, {icmpv6: false}));
                                        }} name="icmpv6"/>
                                    }
                                    label="ICMPv6"
                                />
                                <FormControlLabel
                                    control={
                                        <Checkbox disabled={!enabled} checked={filter.icmp} onChange={(ev) => {
                                            if (ev.target.checked)
                                                setFilter((f: any) => Object.assign({}, f, {icmp: true}));
                                            else
                                                setFilter((f: any) => Object.assign({}, f, {icmp: false}));
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
                                        <Checkbox disabled={!enabled} checked={filter.http} onChange={(ev) => {
                                            if (ev.target.checked)
                                                setFilter((f: any) => Object.assign({}, f, {http: true}));
                                            else
                                                setFilter((f: any) => Object.assign({}, f, {http: false}));
                                        }} name="http"/>
                                    }
                                    label="HTTP"
                                />
                                <FormControlLabel
                                    control={
                                        <Checkbox disabled={!enabled} checked={filter.tls} onChange={(ev) => {
                                            if (ev.target.checked)
                                                setFilter((f: any) => Object.assign({}, f, {tls: true}));
                                            else
                                                setFilter((f: any) => Object.assign({}, f, {tls: false}));
                                        }} name="tls"/>
                                    }
                                    label="TLS"
                                />
                                <FormControlLabel
                                    control={
                                        <Checkbox disabled={!enabled} checked={filter.dns} onChange={(ev) => {
                                            if (ev.target.checked)
                                                setFilter((f: any) => Object.assign({}, f, {dns: true}));
                                            else
                                                setFilter((f: any) => Object.assign({}, f, {dns: false}));
                                        }} name="dns"/>
                                    }
                                    label="DNS"
                                />
                            </FormGroup>
                        </FormControl>
                        <FormControl sx={{m: 3}} component="fieldset" variant="standard">
                            <FormGroup>
                                <FormControlLabel className={"text-field"}
                                                  control={
                                                      <>
                                                          <Checkbox disabled={!enabled} checked={filter.src_ip}
                                                                    onChange={(ev) => {
                                                                        if (ev.target.checked)
                                                                            setFilter((f: any) => Object.assign({}, f, {src_ip: true}));
                                                                        else
                                                                            setFilter((f: any) => Object.assign({}, f, {src_ip: false}));
                                                                    }} name="src_ip"/>
                                                          <TextField disabled={!enabled}
                                                              onChange={(s) => setSrcIpForm(s.target.value)}
                                                              id="src_ip" label="SOURCE IP" variant="standard"/>
                                                      </>
                                                  }
                                                  label=""
                                />
                                <FormControlLabel className={"text-field"}
                                                  control={
                                                      <>
                                                          <Checkbox disabled={!enabled} checked={filter.dst_ip}
                                                                    onChange={(ev) => {
                                                                        if (ev.target.checked)
                                                                            setFilter((f: any) => Object.assign({}, f, {dst_ip: true}));
                                                                        else
                                                                            setFilter((f: any) => Object.assign({}, f, {dst_ip: false}));
                                                                    }} name="dst_ip"/>
                                                          <TextField disabled={!enabled}
                                                              onChange={(s) => setDstIpForm(s.target.value)}
                                                              id="dst_ip" label="DESTINATION IP" variant="standard"/>
                                                      </>
                                                  }
                                                  label=""
                                />
                                <FormControlLabel className={"text-field"}
                                                  control={
                                                      <>
                                                          <Checkbox disabled={!enabled} checked={filter.src_mac}
                                                                    onChange={(ev) => {
                                                                        if (ev.target.checked)
                                                                            setFilter((f: any) => Object.assign({}, f, {src_mac: true}));
                                                                        else
                                                                            setFilter((f: any) => Object.assign({}, f, {src_mac: false}));
                                                                    }} name="src_mac"/>
                                                          <TextField disabled={!enabled}
                                                              onChange={(s) => setSrcMacForm(s.target.value)}
                                                              id="src_mac" label="SOURCE MAC" variant="standard"/>
                                                      </>
                                                  }
                                                  label=""
                                />
                                <FormControlLabel className={"text-field"}
                                                  control={
                                                      <>
                                                          <Checkbox disabled={!enabled} checked={filter.dst_mac}
                                                                    onChange={(ev) => {
                                                                        if (ev.target.checked)
                                                                            setFilter((f: any) => Object.assign({}, f, {dst_mac: true}));
                                                                        else
                                                                            setFilter((f: any) => Object.assign({}, f, {dst_mac: false}));
                                                                    }} name="dst_mac"/>
                                                          <TextField disabled={!enabled}
                                                              onChange={(s) => setDstMacForm(s.target.value)}
                                                              id="dst_mac" label="DESTINATION MAC" variant="standard"/>
                                                      </>
                                                  }
                                                  label=""
                                />
                            </FormGroup>
                        </FormControl>
                        <FormControl sx={{m: 3}} component="fieldset" variant="standard">
                            <FormGroup>
                                <FormControlLabel className={"text-field"}
                                                  control={
                                                      <>
                                                          <Checkbox disabled={!enabled} checked={filter.src_port}
                                                                    onChange={(ev) => {
                                                                        if (ev.target.checked)
                                                                            setFilter((f: any) => Object.assign({}, f, {src_port: true}));
                                                                        else
                                                                            setFilter((f: any) => Object.assign({}, f, {src_port: false}));
                                                                    }} name="src_port"/>
                                                          <TextField disabled={!enabled}
                                                              onChange={(s) => setSrcPortForm(s.target.value)}
                                                              id="src_port" label="SOURCE PORT" variant="standard"/>
                                                      </>
                                                  }
                                                  label=""
                                />
                                <FormControlLabel className={"text-field"}
                                                  control={
                                                      <>
                                                          <Checkbox disabled={!enabled} checked={filter.dst_port}
                                                                    onChange={(ev) => {
                                                                        if (ev.target.checked)
                                                                            setFilter((f: any) => Object.assign({}, f, {dst_port: true}));
                                                                        else
                                                                            setFilter((f: any) => Object.assign({}, f, {dst_port: false}));
                                                                    }} name="dst_port"/>
                                                          <TextField disabled={!enabled}
                                                              onChange={(s) => setDstPortForm(s.target.value)}
                                                              id="dst_port" label="DESTINATION PORT"
                                                              variant="standard"/>
                                                      </>
                                                  }
                                                  label=""
                                />
                                <FormControlLabel className={"text-field"}
                                                  control={
                                                      <>
                                                          <Checkbox disabled={!enabled} checked={filter.info}
                                                                    onChange={(ev) => {
                                                                        if (ev.target.checked)
                                                                            setFilter((f: any) => Object.assign({}, f, {info: true}));
                                                                        else
                                                                            setFilter((f: any) => Object.assign({}, f, {info: false}));
                                                                    }} name="info"/>
                                                          <TextField disabled={!enabled}
                                                              onChange={(s) => setInfoForm(s.target.value)}
                                                              id="info" label="Packet Info" variant="standard"/>
                                                      </>
                                                  }
                                                  label=""
                                />
                            </FormGroup>
                        </FormControl>
                    </Box>
                </AccordionDetails>
            </Accordion>
        </Grid>
    );
}

export default Filters;