import * as React from 'react';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import './custom.css'
import {
    Accordion,
    AccordionDetails,
    AccordionSummary,
    FormControl,
    FormControlLabel,
    Grid,
    InputLabel,
    MenuItem,
    Select,
    Switch,
    TextField
} from '@mui/material';

const Dashboard = () => {
    const [expand, setExpand] = React.useState(false);
    const toggleAcordion = () => {
        setExpand((prev) => !prev);
    };

    return (
        <>
            <Accordion expanded={expand} className='dash'>
                <AccordionSummary expandIcon={''}>
                    <Grid container spacing={1}>
                        <Grid item xs={12}>
                            <FormControlLabel className='switch'
                                              control={<Switch color='success' onChange={toggleAcordion}/>}
                                              label="Generate Report"/>
                        </Grid>
                        <Grid item xs={8} style={{"borderRadius": "10px"}}>
                            <FormControl variant="filled" className='select'>
                                <InputLabel color='success' id="demo-simple-select-filled-label">Select
                                    Interface</InputLabel>
                                <Select
                                    color='success'
                                    labelId="demo-simple-select-filled-label"
                                    id="demo-simple-select-filled"
                                >
                                    <MenuItem value={10}>Ten</MenuItem>
                                    <MenuItem value={20}>Twenty</MenuItem>
                                    <MenuItem value={30}>Thirty</MenuItem>
                                </Select>
                            </FormControl>
                        </Grid>
                        <Grid item xs={4}>
                            <Grid container>
                                <Grid item xs={2}>
                                    <div className='play-container'>
                                        <div className='start-background'>
                                            <PlayArrowIcon className='play-icon'/>
                                        </div>
                                    </div>
                                </Grid>
                                <Grid item xs={1}/>
                                <span className='span-new'>New Session</span>
                            </Grid>
                        </Grid>
                    </Grid>
                </AccordionSummary>
                <AccordionDetails>
                    <Grid container>
                        <Grid item xs={6}>
                            <TextField
                                color="success"
                                InputLabelProps={{
                                    style: {
                                        color: '#9AFF76',
                                        opacity: '60%',
                                        fontFamily: 'Source Code Pro'
                                    }
                                }}
                                sx={{input: {color: "white", fontFamily: 'Source Code Pro'}}}
                                className='input' id="standard-basic" label="Report Name" variant="standard"/>
                        </Grid>
                        <Grid item xs={6}>
                            <TextField
                                color="success"
                                InputLabelProps={{
                                    style: {
                                        color: '#9AFF76',
                                        opacity: '60%',
                                        fontFamily: 'Source Code Pro'
                                    }
                                }}
                                sx={{input: {color: "white", fontFamily: 'Source Code Pro'}}}
                                className='input' id="standard-basic" label="Report Folder" variant="standard"/>
                        </Grid>
                    </Grid>
                </AccordionDetails>
            </Accordion>
        </>
    )
}

export default Dashboard;