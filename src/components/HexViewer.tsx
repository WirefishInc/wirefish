import {FC} from "react";
import {Grid} from "@mui/material";

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

interface RowProps {
    row: string[];
    i: number;
    over: string | null;
    setOver: (params: any) => any;
}

const Row: FC<RowProps> = ({row, i, over, setOver}) => {
    return (
        <>
            {
                row.map((el, j) =>
                    <td key={i * 16 + j} id={(i * 16 + j).toString()}
                        onMouseOver={(ev) => {
                            // @ts-ignore
                            setOver(ev.target.id.toString())
                        }}
                        onMouseLeave={(ev) => {
                            setOver("")
                        }}
                        className={over === (i * 16 + j).toString() ? "hex active" : "hex"}>{el}</td>
                )
            }
        </>
    )

}

interface HewViewerProps {
    payload: number[]; // dec
    over: string | null;
    setOver: (params: any) => any;
}

const HewViewer: FC<HewViewerProps> = ({payload, over, setOver}) => {
    if (payload.length === 0)
        return null;

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
        <Grid container spacing={2} className={"container-main"}>
            <Grid xs={12} item={true}>
                <Grid container spacing={2} className={"container-main viewer"}>
                    <Grid item xs={6}>
                        <table>
                            <tbody>
                            {hew_rows.map((r, i) =>
                                <tr>
                                    {<td className={"index"}>{"0x" + (i * 16).toString(16).toUpperCase()}</td>}
                                    {<td className={"index"}>|</td>}
                                    <Row row={r} i={i} over={over} setOver={setOver}/>
                                </tr>
                            )}
                            </tbody>
                        </table>
                    </Grid>
                    <Grid item xs={6}>
                        <table className={"ascii"}>
                            <tbody>
                            {ascii_rows.map((r, i) =>
                                <tr>
                                    <Row row={r} i={i} over={over} setOver={setOver}/>
                                </tr>
                            )}
                            </tbody>
                        </table>
                    </Grid>
                </Grid>
            </Grid>
        </Grid>
    )
}


export default HewViewer;