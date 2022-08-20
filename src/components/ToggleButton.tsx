import {Button} from "@mui/material";
import {ReactElement} from "react";

type ToggleButtonProps = {
    toggleFunction: Function,
    disabled: boolean,
    condition: boolean,
    textTrue: string,
    textFalse: string,
    iconTrue: ReactElement,
    iconFalse: ReactElement
}

const ToggleButton = ({
                          toggleFunction,
                          disabled,
                          condition,
                          textFalse,
                          textTrue,
                          iconFalse,
                          iconTrue
                      }: ToggleButtonProps) => {
    return (
        <Button variant="contained" onClick={() => toggleFunction()} className={"button-command"}
                size="large" disabled={disabled}>
            <>
                <span>{condition ? textTrue : textFalse}</span>
                {condition ? iconTrue : iconFalse}
            </>
        </Button>
    );
}

export default ToggleButton;