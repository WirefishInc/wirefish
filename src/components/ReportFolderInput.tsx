import {FormControl, FormHelperText, TextField} from "@mui/material";
import {SniffingStatus} from "../types/sniffing";
import {open} from '@tauri-apps/api/dialog';
import {appDir} from '@tauri-apps/api/path';
import {useState} from "react";

const selectDirectory = async (originalDirectory: string | null) => {
    let directory = originalDirectory;
    try {
        let result = await open({
            directory: true,
            multiple: false,
            defaultPath: await appDir(),
        });
        if (Array.isArray(result)) {
            result = result[0];
        }
        directory = result || directory;
    } catch (NoDirectorySelected) {
    }
    return directory;
}

type ReportFolderInputProps = {
    reportFolder: string,
    setReportFolder: Function,
    sniffingStatus: SniffingStatus,
    validated: boolean
}

const ReportFolderInput = ({
                               reportFolder,
                               setReportFolder,
                               sniffingStatus,
                               validated
                           }: ReportFolderInputProps) => {

    let [selectingFolder, setSelectingFolder] = useState(false);
    const setReportFolderWrapper = async () => {
        if(!selectingFolder) {
            setSelectingFolder(true);
            // @ts-ignore
            const separator = window.__TAURI__.path.sep;
            let folder = await selectDirectory(reportFolder);
            if (folder && !folder.endsWith(separator))
                folder += separator;
            setReportFolder(folder);
            setSelectingFolder(false);
        }
    }

    const reportFolderError = validated && reportFolder.length < 1;
    return (
        <FormControl error={reportFolderError} variant="standard" sx={{mt: 3, width: "100%"}}>
            <TextField
                label="Report folder"
                value={reportFolder}
                error={reportFolderError}
                disabled={sniffingStatus !== SniffingStatus.Inactive || selectingFolder}
                onClick={setReportFolderWrapper}
                onChange={setReportFolderWrapper}
            />
            {
                reportFolderError &&
                <FormHelperText id="component-error-text">
                    Please provide a folder
                </FormHelperText>
            }
        </FormControl>
    )
}

export default ReportFolderInput;