import React from 'react';
import {FormControl, FormHelperText, InputLabel, MenuItem, Select} from "@mui/material";
import {SniffingStatus} from "../types/sniffing";

type InterfaceInputProps = {
    sniffingStatus: SniffingStatus,
    currentInterface: string,
    selectInterface: Function,
    interfaces: string[] | null,
    validated: boolean
}

const InterfaceInput = (
    {
        sniffingStatus,
        currentInterface,
        selectInterface,
        interfaces,
        validated
    }: InterfaceInputProps) => {

    const interfaceError = validated && currentInterface.length === 0;

    return (
        <FormControl style={{width: "100%"}} error={interfaceError}>
            <InputLabel>Interface</InputLabel>
            <Select value={currentInterface} label="Interface" defaultValue={null}
                    error={interfaceError}
                    disabled={sniffingStatus !== SniffingStatus.Inactive}
                    sx={{m: 0, display: "block"}}
                    onChange={(e) => selectInterface(e.target.value as string)}>
                {
                    interfaces?.map((i) => <MenuItem key={i} value={i}>{i}</MenuItem>)
                }
            </Select>
            {
                interfaceError &&
                <FormHelperText id="component-error-text">
                    Please select an interface
                </FormHelperText>
            }
        </FormControl>
    )
}

export default InterfaceInput;