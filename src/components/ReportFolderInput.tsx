import {FormControl, FormHelperText, TextField} from "@mui/material";
import {SniffingStatus} from "../types/sniffing";
import {open} from '@tauri-apps/api/dialog';
import {appDir} from '@tauri-apps/api/path';
import {useState} from "react";

const selectDirectory = async (originalDirectory: string | string[] | null) => {
    let directory = originalDirectory;
    try {
        let result = await open({
            directory: true,
            multiple: false,
            defaultPath: await appDir(),
        });
        directory = result || directory;
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

    let [selectingFolder, setSelectingFolder] = useState(false);
    const setReportFolderWrapper = async () => {
        setSelectingFolder(true);
        setReportFolder(await selectDirectory(reportFolder));
        setSelectingFolder(false);
    }

    return (
        <FormControl error={reportFolder.length < 1} variant="standard" sx={{mt: 3, width: "100%"}}>
            <TextField
                label="Report folder"
                value={reportFolder}
                error={reportFolder.length < 1}
                disabled={sniffingStatus !== SniffingStatus.Inactive || selectingFolder}
                onChange={setReportFolderWrapper}
                onClick={setReportFolderWrapper}
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