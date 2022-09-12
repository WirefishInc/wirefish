import {FC} from "react";
import {Grid, Table} from "@mui/material";

function payloadToHex(payload: number[]) {
    return payload.reverse().map((el: number) => el.toString(16)).map((el) => el.toUpperCase());
}

function hexToAscii(byte: number) {
    let char = "";

    if (byte > 31 && byte < 127) {
        char = String.fromCharCode(byte);
    } else {
        char = "·";
    }

    return char;
}

interface HewViewerProps {
    payload: number[]; // dec
    over: string | null;
    setOver: (params: any) => any;
}

const HewViewer: FC<HewViewerProps> = ({payload, over, setOver}) => {
    let hex_payload = payloadToHex(payload);
    let ascii_payload = payload.map((el) => hexToAscii(el));

    let hew_rows = [];
    let ascii_rows = [];

    while (hex_payload.length) {
        hew_rows.push(hex_payload.splice(0, 16))
    }

    while (ascii_payload.length) {
        ascii_rows.push(ascii_payload.splice(0, 16))
    }

    return (
        <Grid className={"payload"} container spacing={2}>
            <Grid item xs={6}>

                <Table>
                    <tbody>
                    {hew_rows.map((r, i) =>
                        <tr>
                            {<td className={"index"}>{"0x" + (i * 16).toString(16).toUpperCase()}</td>}
                            {
                                r.map((el, j) =>
                                    <td id={(i * 16 + j).toString()}
                                        onMouseOver={(ev) => {
                                            // @ts-ignore
                                            setOver(ev.target.id.toString())
                                        }}
                                        onMouseLeave={(ev) => {
                                            setOver("")
                                        }}
                                        className={over === (i * 16 + j).toString() ? "hex active" : "hex"}>{el}</td>
                                )}
                        </tr>
                    )}
                    </tbody>
                </Table>
            </Grid>
            <Grid item xs={6}>
                <table>
                    <tbody>
                    {ascii_rows.map((r, i) =>
                        <tr>
                            {<td className={"index"}>{"0x" + (i * 16).toString(16).toUpperCase()}</td>}
                            {
                                r.map((el, j) =>
                                    <td id={(i * 16 + j).toString()}
                                        onMouseOver={(ev) => {
                                            // @ts-ignore
                                            setOver(ev.target.id.toString())
                                        }}
                                        onMouseLeave={(ev) => {
                                            setOver("")
                                        }}
                                        className={over === (i * 16 + j).toString() ? "hex active" : "hex"}>{el}</td>
                                )}
                        </tr>
                    )}
                    </tbody>
                </table>
            </Grid>
        </Grid>
    )
}


export default HewViewer;