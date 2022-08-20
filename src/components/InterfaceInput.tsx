import React from 'react';
import {FormControl, InputLabel, MenuItem, Select} from "@mui/material";
import {SniffingStatus} from "../types/sniffing";

type InterfaceInputProps = {
    sniffingStatus: SniffingStatus,
    currentInterface: string,
    selectInterface: Function,
    interfaces: string[] | null
}

const InterfaceInput = (
    {
        sniffingStatus,
        currentInterface,
        selectInterface,
        interfaces
    }: InterfaceInputProps) => {
    return (
        <FormControl style={{width: "100%"}}>
            <InputLabel>Interface</InputLabel>
            <Select value={currentInterface} label="Interface" defaultValue={null}
            disabled={sniffingStatus !== SniffingStatus.Inactive}
            sx={{m: 0, display: "block"}}
            onChange={(e) => selectInterface(e.target.value as string)}>
            {
                interfaces?.map((i) => <MenuItem key={i} value={i}>{i}</MenuItem>)
            }
            </Select>
        </FormControl>
    )
}

export default InterfaceInput;