import React, {FC, useState} from "react";
import {
    Accordion,
    AccordionDetails,
    AccordionSummary, Checkbox,
    FormControl,
    FormControlLabel,
    FormGroup,
    FormLabel, Grid, Switch, TextField
} from "@mui/material";
import Box from "@mui/material/Box";
import {FilterList} from "@mui/icons-material";

const IPValidator = require('ip-validator');
const MacValidator = require('is-mac-address')

function ValidateIPaddress(ipaddress: string) {
    return IPValidator.ipv4(ipaddress) || IPValidator.ipv6(ipaddress);
}

function ValidateMacAddress(macaddress: string) {
    return MacValidator.isMACAddress(macaddress)
}

function ValidatePortAddress(portaddress: string) {
    const portRegex = /^([0-9]*)$/;

    return portRegex.test(portaddress);
}

interface FiltersProps {
    filter: any,
    setFilter: any,
    setSrcIpForm: any,
    setDstIpForm: any,
    setSrcMacForm: any,
    setDstMacForm: any,
    setSrcPortForm: any,
    setDstPortForm: any,
    setMakeRequest: any,
    setPageState: any
}

const Filters: FC<FiltersProps> = ({
                                       filter,
                                       setFilter,
                                       setDstIpForm,
                                       setDstMacForm,
                                       setDstPortForm,
                                       setSrcMacForm,
                                       setSrcPortForm,
                                       setSrcIpForm,
                                       setMakeRequest,
                                       setPageState
                                   }) => {

    const [ipSrcInputError, setIpSrcInputError] = useState<boolean>(false);
    const [ipDstInputError, setIpDstInputError] = useState<boolean>(false);
    const [macSrcInputError, setMacSrcInputError] = useState<boolean>(false);
    const [macDstInputError, setMacDstInputError] = useState<boolean>(false);
    const [portSrcInputError, setPortSrcInputError] = useState<boolean>(false);
    const [portDstInputError, setPortDstInputError] = useState<boolean>(false);

    return (
        <Grid xs={12} item={true} className={"container-center"}>
            <Accordion>
                <AccordionSummary className={"center"} expandIcon={<FilterList/>}>
                    Filters
                </AccordionSummary>

                <AccordionDetails>

                    {/* Filters */}

                    <Box sx={{display: 'flex'}}>

                        {/* Link Layer Filters */}

                        <FormControl sx={{m: 3}} component="fieldset" variant="standard">
                            <FormLabel component="legend">Link Layer</FormLabel>
                            <FormGroup>
                                <FormControlLabel
                                    control={
                                        <Checkbox checked={filter.ethernet} onChange={(ev) => {
                                            setPageState(1)
                                            setMakeRequest(true)
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
                                        <Checkbox checked={filter.unknown} onChange={(ev) => {
                                            setPageState(1)
                                            setMakeRequest(true)
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
                                        <Checkbox checked={filter.malformed} onChange={(ev) => {
                                            setPageState(1)
                                            setMakeRequest(true)
                                            if (ev.target.checked)
                                                setFilter((f: any) => Object.assign({}, f, {malformed: true}));
                                            else
                                                setFilter((f: any) => Object.assign({}, f, {malformed: false}));
                                        }} name="malformed"/>
                                    }
                                    label="Malformed"
                                />
                            </FormGroup>

                            {/* Network Layer Filters */}

                        </FormControl>
                        <FormControl sx={{m: 3}} component="fieldset" variant="standard">
                            <FormLabel component="legend">Network Layer</FormLabel>
                            <FormGroup>
                                <FormControlLabel
                                    control={
                                        <Checkbox checked={filter.ipv6} onChange={(ev) => {
                                            setPageState(1)
                                            setMakeRequest(true)
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
                                        <Checkbox checked={filter.ipv4} onChange={(ev) => {
                                            setPageState(1)
                                            setMakeRequest(true)
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
                                        <Checkbox checked={filter.arp} onChange={(ev) => {
                                            setPageState(1)
                                            setMakeRequest(true)
                                            if (ev.target.checked)
                                                setFilter((f: any) => Object.assign({}, f, {arp: true}));
                                            else
                                                setFilter((f: any) => Object.assign({}, f, {arp: false}));
                                        }} name="arp"/>
                                    }
                                    label="ARP"
                                />
                                <FormControlLabel
                                    control={
                                        <Checkbox checked={filter.icmpv6} onChange={(ev) => {
                                            setPageState(1)
                                            setMakeRequest(true)
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
                                        <Checkbox checked={filter.icmp} onChange={(ev) => {
                                            setPageState(1)
                                            setMakeRequest(true)
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

                        {/* Transport Layer Filters */}

                        <FormControl sx={{m: 3}} component="fieldset" variant="standard">
                            <FormLabel component="legend">Transport Layer</FormLabel>
                            <FormGroup>
                                <FormControlLabel
                                    control={
                                        <Checkbox checked={filter.tcp} onChange={(ev) => {
                                            setPageState(1)
                                            setMakeRequest(true)
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
                                        <Checkbox checked={filter.udp} onChange={(ev) => {
                                            setPageState(1)
                                            setMakeRequest(true)
                                            if (ev.target.checked)
                                                setFilter((f: any) => Object.assign({}, f, {udp: true}));
                                            else
                                                setFilter((f: any) => Object.assign({}, f, {udp: false}));
                                        }} name="udp"/>
                                    }
                                    label="UDP"
                                />
                            </FormGroup>
                        </FormControl>

                        {/* Application Layer Filters */}

                        <FormControl sx={{m: 3}} component="fieldset" variant="standard">
                            <FormLabel component="legend">Application Layer</FormLabel>
                            <FormGroup>
                                <FormControlLabel
                                    control={
                                        <Checkbox checked={filter.http} onChange={(ev) => {
                                            setPageState(1)
                                            setMakeRequest(true)
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
                                        <Checkbox checked={filter.tls} onChange={(ev) => {
                                            setPageState(1)
                                            setMakeRequest(true)
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
                                        <Checkbox checked={filter.dns} onChange={(ev) => {
                                            setPageState(1)
                                            setMakeRequest(true)
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

                        {/* Other Filters */}

                        <FormControl sx={{m: 3}} component="fieldset" variant="standard">
                            <FormGroup>
                                <FormControlLabel className={"text-field"}
                                                  control={
                                                      <>
                                                          <TextField
                                                              error={ipSrcInputError}
                                                              onChange={(s) => {
                                                                  if (s.target.value === "") {
                                                                      setIpSrcInputError(false);
                                                                      setMakeRequest(true);
                                                                      setPageState(1);
                                                                      setMakeRequest(true);
                                                                      setSrcIpForm(s.target.value)
                                                                  } else {
                                                                      if (ValidateIPaddress(s.target.value)) {
                                                                          setIpSrcInputError(false);
                                                                          setPageState(1);
                                                                          setMakeRequest(true);
                                                                          setSrcIpForm(s.target.value)
                                                                      } else {
                                                                          setIpSrcInputError(true);
                                                                      }
                                                                  }
                                                              }}
                                                              id="src_ip" label="SOURCE IP" variant="standard"/>
                                                      </>
                                                  }
                                                  label=""
                                />
                                <FormControlLabel className={"text-field"}
                                                  control={
                                                      <>
                                                          <TextField
                                                              error={ipDstInputError}
                                                              onChange={(s) => {
                                                                  if (s.target.value === "") {
                                                                      setIpDstInputError(false);
                                                                      setMakeRequest(true);
                                                                      setDstIpForm(s.target.value)
                                                                  } else {
                                                                      if (ValidateIPaddress(s.target.value)) {
                                                                          setIpDstInputError(false);
                                                                          setPageState(1);
                                                                          setMakeRequest(true);
                                                                          setDstIpForm(s.target.value)
                                                                      } else {
                                                                          setIpDstInputError(true);
                                                                      }
                                                                  }

                                                              }}
                                                              id="dst_ip" label="DESTINATION IP"
                                                              variant="standard"/>
                                                      </>
                                                  }
                                                  label=""
                                />
                                <FormControlLabel className={"text-field"}
                                                  control={
                                                      <>
                                                          <TextField
                                                              error={macSrcInputError}
                                                              onChange={(s) => {
                                                                  if (s.target.value === "") {
                                                                      setMacSrcInputError(false);
                                                                      setMakeRequest(true);
                                                                      setSrcMacForm(s.target.value)
                                                                  } else {
                                                                      if (ValidateMacAddress(s.target.value)) {
                                                                          setMacSrcInputError(false);
                                                                          setPageState(1);
                                                                          setMakeRequest(true);
                                                                          setSrcMacForm(s.target.value)
                                                                      } else {
                                                                          setMacSrcInputError(true);
                                                                      }
                                                                  }

                                                              }}
                                                              id="src_mac" label="SOURCE MAC"
                                                              variant="standard"/>
                                                      </>
                                                  }
                                                  label=""
                                />
                                <FormControlLabel className={"text-field"}
                                                  control={
                                                      <>
                                                          <TextField
                                                              error={macDstInputError}
                                                              onChange={(s) => {
                                                                  if (s.target.value === "") {
                                                                      setMacDstInputError(false);
                                                                      setMakeRequest(true);
                                                                      setDstMacForm(s.target.value)
                                                                  } else {
                                                                      if (ValidateMacAddress(s.target.value)) {
                                                                          setMacDstInputError(false);
                                                                          setPageState(1);
                                                                          setMakeRequest(true);
                                                                          setDstMacForm(s.target.value)
                                                                      } else {
                                                                          setMacDstInputError(true);
                                                                      }
                                                                  }
                                                              }}
                                                              id="dst_mac" label="DESTINATION MAC"
                                                              variant="standard"/>
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
                                                          <TextField
                                                              error={portSrcInputError}
                                                              onChange={(s) => {
                                                                  if (s.target.value === "") {
                                                                      setPortSrcInputError(false);
                                                                      setMakeRequest(true);
                                                                      setSrcPortForm(s.target.value)
                                                                  } else {
                                                                      if (ValidatePortAddress(s.target.value)) {
                                                                          setPortSrcInputError(false);
                                                                          setPageState(1);
                                                                          setMakeRequest(true);
                                                                          setSrcPortForm(s.target.value)
                                                                      } else {
                                                                          setPortSrcInputError(true);
                                                                      }
                                                                  }

                                                              }}
                                                              id="src_port" label="SOURCE PORT"
                                                              variant="standard"/>
                                                      </>
                                                  }
                                                  label=""
                                />
                                <FormControlLabel className={"text-field"}
                                                  control={
                                                      <>
                                                          <TextField
                                                              error={portDstInputError}
                                                              onChange={(s) => {
                                                                  if (s.target.value === "") {
                                                                      setPortDstInputError(false);
                                                                      setMakeRequest(true);
                                                                      setDstPortForm(s.target.value)
                                                                  } else {
                                                                      if (ValidatePortAddress(s.target.value)) {
                                                                          setPortDstInputError(false);
                                                                          setPageState(1);
                                                                          setMakeRequest(true);
                                                                          setDstPortForm(s.target.value)
                                                                      } else {
                                                                          setPortDstInputError(true);
                                                                      }
                                                                  }
                                                              }}
                                                              id="dst_port" label="DESTINATION PORT"
                                                              variant="standard"/>
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