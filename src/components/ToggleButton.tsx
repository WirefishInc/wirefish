import {Button} from "@mui/material";
import {ReactElement} from "react";
import CircularProgress from '@mui/material/CircularProgress';
import Box from '@mui/material/Box';

type ToggleButtonProps = {
    toggleFunction: Function,
    disabled: boolean,
    condition: boolean,
    loading: boolean,
    textTrue: string,
    textFalse: string,
    iconTrue: ReactElement,
    iconFalse: ReactElement,
    setInputValidated: Function | null
}

const ToggleButton = ({
                          toggleFunction,
                          disabled,
                          condition,
                          loading,
                          textFalse,
                          textTrue,
                          iconFalse,
                          iconTrue,
                          setInputValidated
                      }: ToggleButtonProps) => {

    const loader =
        <Box sx={{display: 'inline-flex', paddingLeft: "5px"}}>
            <CircularProgress style={{width: "16px", height: "16px"}}/>
        </Box>;

    const handleOuterClick = () => {
        if (setInputValidated)
            setInputValidated(true);
    };

    return (
        <div onClick={handleOuterClick}>
            <Button variant="contained" onClick={() => toggleFunction()}
                    className={"button-command"} size="large" disabled={disabled}>
                <>
                    <span>{condition ? textTrue : textFalse}</span>
                    {loading ? loader : (condition ? iconTrue : iconFalse)}
                </>
            </Button>
        </div>
    );
}

export default ToggleButton;