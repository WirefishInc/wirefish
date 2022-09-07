import {FC} from "react";
import {Divider, ListItem} from "@mui/material";

interface FieldProps {
    packetInfo: [];
}

const Fields: FC<FieldProps> = ({packetInfo}) => {
    let fields = [];

    for (const el of packetInfo) {
        fields.push(
            <>
                <ListItem key={fields.length}><> {Object.keys(el)[0]} : {Object.values(el)[0]} </>
                </ListItem>
                <Divider/>
            </>
        )
    }

    return (
        <>{fields}</>
    );
};

export default Fields;