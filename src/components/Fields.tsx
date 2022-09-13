import {FC} from "react";
import {Accordion, AccordionDetails, AccordionSummary, Divider, List, ListItem} from "@mui/material";
import {CustomTlsMessages} from "../serializable_packet/tls";
import {ArrowDropDown} from "@mui/icons-material";
import '../index.css';

interface FieldProps {
    packetInfo: [];
}

const Fields: FC<FieldProps> = ({packetInfo}) => {
    let fields = [];

    for (const el of packetInfo) {
        fields.push(
            <>
                <ListItem className={"break"} key={fields.length}><> {Object.keys(el)[0]} : {Object.values(el)[0]} </>
                </ListItem>
                <Divider/>
            </>
        )
    }

    return (
        <>{fields}</>
    );
};

interface TlsFieldProps {
    packetInfo: CustomTlsMessages[];
}

const TlsFields: FC<TlsFieldProps> = ({packetInfo}) => {
    let fields = [];

    for (const el of packetInfo) {
        fields.push(
            <>
                <ListItem>
                    <Accordion className={"inner-acc"}>
                        <AccordionSummary expandIcon={<ArrowDropDown/>}>
                            {el.toString()}
                        </AccordionSummary>
                        <AccordionDetails>
                            <List className={"break"} key={fields.length} component="nav" aria-label="mailbox folders">
                                <Fields
                                    packetInfo={el.toDisplay()}/>
                            </List>
                        </AccordionDetails>
                    </Accordion>
                </ListItem>
                <Divider/>
            </>
        )
    }

    return (
        <>{fields}</>
    );
};

export {Fields, TlsFields};