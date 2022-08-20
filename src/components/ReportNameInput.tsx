import {FormControl, FormHelperText, InputAdornment, TextField} from "@mui/material";
import {SniffingStatus} from "../types/sniffing";

type ReportNameInputProps = {
    reportFileName: string,
    setReportFileName: Function,
    sniffingStatus: SniffingStatus
}

const ReportNameInput = ({
                             reportFileName,
                             setReportFileName,
                             sniffingStatus
                           }: ReportNameInputProps) => {
    return (
        <FormControl error={reportFileName.length < 1} variant="standard" sx={{mt: 3, width: "100%"}}>
            <TextField
                label="Report file name"
                value={reportFileName}
                error={reportFileName.length < 1}
                disabled={sniffingStatus !== SniffingStatus.Inactive}
                onChange={(e) => setReportFileName(e.target.value)}
                InputProps={{
                    inputProps: {className: "filename-input"},
                    endAdornment: <InputAdornment position="end">.txt</InputAdornment>,
                }}
            />
            {
                reportFileName.length < 1 &&
                <FormHelperText id="component-error-text">
                    Please provide a file name
                </FormHelperText>
            }
        </FormControl>
    )
}
export default ReportNameInput;