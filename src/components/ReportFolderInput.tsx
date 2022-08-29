import {FormControl, FormHelperText, TextField} from "@mui/material";
import {SniffingStatus} from "../types/sniffing";
import {open} from '@tauri-apps/api/dialog';
import {appDir} from '@tauri-apps/api/path';

const selectDirectory = async (originalDirectory: string | string[] | null) => {
    let directory = originalDirectory;
    try {
        directory = await open({
            directory: true,
            multiple: true,
            defaultPath: await appDir(),
        });
    } catch (NoDirectorySelected) {}
    return directory;
}

type ReportFolderInputProps = {
    reportFolder: string,
    setReportFolder: Function,
    sniffingStatus: SniffingStatus
}

const ReportFolderInput = ({
                               reportFolder,
                               setReportFolder,
                               sniffingStatus
                           }: ReportFolderInputProps) => {
    return (
        <FormControl error={reportFolder.length < 1} variant="standard" sx={{mt: 3, width: "100%"}}>
            <TextField
                label="Report folder"
                value={reportFolder}
                error={reportFolder.length < 1}
                disabled={sniffingStatus !== SniffingStatus.Inactive}
                onChange={async (e) => setReportFolder(await selectDirectory(reportFolder))}
                onClick={async (e) => setReportFolder(await selectDirectory(reportFolder))}
            />
            {
                reportFolder.length < 1 &&
                <FormHelperText id="component-error-text">
                    Please provide a folder
                </FormHelperText>
            }
        </FormControl>
    )
}

export default ReportFolderInput;