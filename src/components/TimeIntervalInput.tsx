import {FormControl, FormHelperText, InputAdornment, TextField} from "@mui/material";
import {SniffingStatus} from "../types/sniffing";

type TimeIntervalInputProps = {
    reportUpdateTime: number,
    setReportUpdateTime: Function,
    sniffingStatus: SniffingStatus
}

const TimeIntervalInput = ({
                               reportUpdateTime,
                               setReportUpdateTime,
                               sniffingStatus
                           }: TimeIntervalInputProps) => {
    return (
        <FormControl error={reportUpdateTime < 1} variant="standard" sx={{mt: 3, width: "100%", pr: 3}}>
            <TextField
                label="Report update interval"
                type="number"
                disabled={sniffingStatus !== SniffingStatus.Inactive}
                value={reportUpdateTime}
                error={reportUpdateTime < 1}
                onChange={(e) => setReportUpdateTime(Number(e.target.value))}
                InputProps={{
                    inputProps: {min: 1},
                    endAdornment: <InputAdornment position="end">seconds</InputAdornment>,
                }}
            />
            {
                reportUpdateTime < 1 &&
                <FormHelperText id="component-error-text">
                    Please select a value greater than 1
                </FormHelperText>
            }
        </FormControl>
    )
}
export default TimeIntervalInput;