import {FC} from "react";
import {Accordion, AccordionDetails, AccordionSummary, Divider, List, ListItem, Paper} from "@mui/material";
import {ArrowDropDown} from "@mui/icons-material";
import '../index.css';

interface FieldProps {
    packetInfo: any[];
}

const Fields: FC<FieldProps> = ({packetInfo}) => {
    return (
        <>
            {packetInfo.map((el, i) => {
                return (
                    <>
                        {
                            Object.keys(el)[0] === "HTTPResp" || Object.keys(el)[0] === "HTTPReq" ?
                                <ListItem className={"break"} key={i}>
                                    <Accordion className={"inner-acc"}>
                                        <AccordionSummary expandIcon={<ArrowDropDown/>}>
                                            {// @ts-ignore
                                                Object.values(el)[0].type}
                                        </AccordionSummary>
                                        <AccordionDetails>
                                            {// @ts-ignore
                                                Object.values(el)[0].content}
                                        </AccordionDetails>
                                    </Accordion>
                                </ListItem>
                                :
                                <ListItem className={"break"}
                                          key={i}><> {Object.keys(el)[0]} : {Object.values(el)[0]} </>
                                </ListItem>
                        }
                        <Divider/>
                    </>
                )
            })}
        </>
    )
};

interface TlsFieldProps {
    packetInfo: any[];
}

const TlsFields: FC<TlsFieldProps> = ({packetInfo}) => {
    return (
        <>
            {
                packetInfo.map((el, i) => {
                    return (
                        <>
                            <ListItem key={i}>
                                <Accordion className={"inner-acc"}>
                                    <AccordionSummary expandIcon={<ArrowDropDown/>}>
                                        {el.name}
                                    </AccordionSummary>
                                    <AccordionDetails>
                                        {!Array.isArray(el.fields) ?
                                            el.fields.certificateList.map((c: []) =>
                                                <>
                                                    <Paper className={"paper"} elevation={24}>
                                                        <Fields packetInfo={c}/>
                                                    </Paper>
                                                </>
                                            )
                                            :
                                            <List className={"break"} key={i} component="nav"
                                                  aria-label="mailbox folders">
                                                <Fields
                                                    packetInfo={el.fields}/>
                                            </List>
                                        }
                                    </AccordionDetails>
                                </Accordion>
                            </ListItem>
                            <Divider/>
                        </>
                    )
                })
            }
        </>
    )
};

interface DnsFieldProps {
    packetInfo: any;
}

const DnsFields: FC<DnsFieldProps> = ({packetInfo}) => {
    let fields = [];

    for (const el of packetInfo.header) {
        fields.push(
            <>
                <ListItem className={"break"}
                          key={fields.length}><> {Object.keys(el)[0]} : {Object.values(el)[0]} </>
                </ListItem>
                <Divider/>
            </>
        )
    }

    if (packetInfo.questions.length > 0) {
        fields.push(
            <>
                <ListItem key={fields.length}>
                    <Accordion className={"inner-acc"}>
                        <AccordionSummary expandIcon={<ArrowDropDown/>}>
                            Questions
                        </AccordionSummary>
                        <AccordionDetails>
                            <List className={"break"} key={fields.length} component="nav" aria-label="mailbox folders">
                                {packetInfo.questions.map((el: any, i: number) =>
                                    <>
                                        <ListItem key={i}>
                                            <Accordion className={"d-inner-acc"}>
                                                <AccordionSummary expandIcon={<ArrowDropDown/>}>
                                                    {el.name}
                                                </AccordionSummary>
                                                <AccordionDetails>
                                                    <List className={"break"} key={fields.length} component="nav"
                                                          aria-label="mailbox folders">
                                                        <Fields
                                                            packetInfo={el.fields}/>
                                                    </List>
                                                </AccordionDetails>
                                            </Accordion>
                                        </ListItem>
                                        <Divider/>
                                    </>)}
                            </List>
                        </AccordionDetails>
                    </Accordion>
                </ListItem>
                <Divider/>
            </>
        )
    }

    if (packetInfo.answers.length > 0) {
        fields.push(
            <>
                <ListItem key={fields.length}>
                    <Accordion className={"inner-acc"}>
                        <AccordionSummary expandIcon={<ArrowDropDown/>}>
                            Answers
                        </AccordionSummary>
                        <AccordionDetails>
                            <List className={"break"} key={fields.length} component="nav" aria-label="mailbox folders">
                                {packetInfo.answers.map((el: any, i: number) =>
                                    <>
                                        <ListItem key={i}>
                                            <Accordion className={"d-inner-acc"}>
                                                <AccordionSummary expandIcon={<ArrowDropDown/>}>
                                                    {el.name}
                                                </AccordionSummary>
                                                <AccordionDetails>
                                                    <List className={"break"} key={fields.length} component="nav"
                                                          aria-label="mailbox folders">
                                                        <Fields
                                                            packetInfo={el.fields}/>
                                                    </List>
                                                    <Paper className={"paper"} elevation={24}>
                                                        <Fields packetInfo={el.data}/>
                                                    </Paper>
                                                </AccordionDetails>
                                            </Accordion>
                                        </ListItem>
                                        <Divider/>
                                    </>)}
                            </List>
                        </AccordionDetails>
                    </Accordion>
                </ListItem>
                <Divider/>
            </>
        )
    }

    if (packetInfo.nameservers.length > 0) {
        fields.push(
            <>
                <ListItem key={fields.length}>
                    <Accordion className={"inner-acc"}>
                        <AccordionSummary expandIcon={<ArrowDropDown/>}>
                            Name servers
                        </AccordionSummary>
                        <AccordionDetails>
                            <List className={"break"} key={fields.length} component="nav" aria-label="mailbox folders">
                                {packetInfo.nameservers.map((el: any, i: number) =>
                                    <>
                                        <ListItem key={i}>
                                            <Accordion className={"d-inner-acc"}>
                                                <AccordionSummary expandIcon={<ArrowDropDown/>}>
                                                    {el.name}
                                                </AccordionSummary>
                                                <AccordionDetails>
                                                    <List className={"break"} key={fields.length} component="nav"
                                                          aria-label="mailbox folders">
                                                        <Fields
                                                            packetInfo={el.fields}/>
                                                    </List>
                                                    <Paper className={"paper"} elevation={24}>
                                                        <Fields packetInfo={el.data}/>
                                                    </Paper>
                                                </AccordionDetails>
                                            </Accordion>
                                        </ListItem>
                                        <Divider/>
                                    </>)}
                            </List>
                        </AccordionDetails>
                    </Accordion>
                </ListItem>
                <Divider/>
            </>
        )
    }

    if (packetInfo.additional.length > 0) {
        fields.push(
            <>
                <ListItem key={fields.length}>
                    <Accordion className={"inner-acc"}>
                        <AccordionSummary expandIcon={<ArrowDropDown/>}>
                            Additional
                        </AccordionSummary>
                        <AccordionDetails>
                            <List className={"break"} key={fields.length} component="nav" aria-label="mailbox folders">
                                {packetInfo.additional.map((el: any, i: number) =>
                                    <>
                                        <ListItem key={i}>
                                            <Accordion className={"d-inner-acc"}>
                                                <AccordionSummary expandIcon={<ArrowDropDown/>}>
                                                    {el.name}
                                                </AccordionSummary>
                                                <AccordionDetails>
                                                    <List className={"break"} key={fields.length} component="nav"
                                                          aria-label="mailbox folders">
                                                        <Fields
                                                            packetInfo={el.fields}/>
                                                    </List>
                                                    <Paper className={"paper"} elevation={24}>
                                                        <Fields packetInfo={el.data}/>
                                                    </Paper>
                                                </AccordionDetails>
                                            </Accordion>
                                        </ListItem>
                                        <Divider/>
                                    </>)}
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

export {Fields, TlsFields, DnsFields};