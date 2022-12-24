import * as React from 'react';
import Typography from '@mui/material/Typography';
import {Button, Checkbox, FormControlLabel, FormGroup, Grid, Input, InputAdornment} from '@mui/material';
import {TwitterPicker} from 'react-color';
import './custom.css'

function SettingsPanel() {
    const [markedColor, setMarkedColor] = React.useState("#3D2427");
    const [ignoredColor, setIgnoredColor] = React.useState("#474747");
    const [markedVisible, setMarkedVisible] = React.useState(false);
    const [ignoredVisible, setIgnoredVisible] = React.useState(false);

    const onToggleMarkedPicker = () => setMarkedVisible(!markedVisible);
    const onToggleIgnoredPicker = () => setIgnoredVisible(!ignoredVisible);

    function handleMarkedColor(color: any) {
        setMarkedColor(color.hex);
    }

    function handleIgnoredColor(color: any) {
        setIgnoredColor(color.hex);
    }

    return (
        <>
            <div className='settingsBg'>
                <Grid container spacing={2}>
                    <Grid item xs={6}>
                        <span className='settingText'>Capture</span>
                        <span className='settingUnderText'>Stop capture after...</span>
                        <FormGroup className='columns'>
                            <FormControlLabel control={<Checkbox sx={{
                                color: 'white',
                                '&.Mui-checked': {
                                    color: 'white',
                                },
                            }}/>} label={<Input size='small' style={{"width": "150px"}} endAdornment={<InputAdornment
                                position="end">packets</InputAdornment>}/>}/>

                            <FormControlLabel control={<Checkbox sx={{
                                color: 'white',
                                '&.Mui-checked': {
                                    color: 'white',
                                },
                            }}/>} label={<Input size='small' style={{"width": "150px"}} endAdornment={<InputAdornment
                                position="end">seconds</InputAdornment>}/>}/>

                            <FormControlLabel control={<Checkbox sx={{
                                color: 'white',
                                '&.Mui-checked': {
                                    color: 'white',
                                },
                            }}/>} label={<Input size='small' style={{"width": "150px"}} endAdornment={<InputAdornment
                                position="end">megabytes</InputAdornment>}/>}/>
                        </FormGroup>
                        <span className='settingText mgt'>Report</span>
                        <span className='settingUnderText'>Create report after...</span>
                        <FormGroup className='columns'>
                            <FormControlLabel control={<Checkbox sx={{
                                color: 'white',
                                '&.Mui-checked': {
                                    color: 'white',
                                },
                            }}/>} label={<Input size='small' style={{"width": "150px"}} endAdornment={<InputAdornment
                                position="end">packets</InputAdornment>}/>}/>
                            <FormControlLabel control={<Checkbox sx={{
                                color: 'white',
                                '&.Mui-checked': {
                                    color: 'white',
                                },
                            }}/>} label={<Input size='small' style={{"width": "150px"}} endAdornment={<InputAdornment
                                position="end">seconds</InputAdornment>}/>}/>
                            <FormControlLabel control={<Checkbox sx={{
                                color: 'white',
                                '&.Mui-checked': {
                                    color: 'white',
                                },
                            }}/>} label={<Input size='small' style={{"width": "150px"}} endAdornment={<InputAdornment
                                position="end">megabytes</InputAdornment>}/>}/>
                            <FormControlLabel control={<Checkbox sx={{
                                color: 'white',
                                '&.Mui-checked': {
                                    color: 'white',
                                },
                            }}/>} label={<Typography style={{"fontFamily": 'Source Code Pro'}}>Repeat after
                                interval</Typography>}/>
                        </FormGroup>
                    </Grid>
                    <Grid item xs={6}>
                        <span className='settingText'>Table Layout</span>
                        <FormGroup className='columns'>
                            <FormControlLabel control={<Checkbox defaultChecked sx={{
                                color: 'white',
                                '&.Mui-checked': {
                                    color: 'white',
                                },
                            }}/>} label={<Typography style={{"fontFamily": 'Source Code Pro'}}>Last Type</Typography>}/>
                            <FormControlLabel control={<Checkbox defaultChecked sx={{
                                color: 'white',
                                '&.Mui-checked': {
                                    color: 'white',
                                },
                            }}/>} label={<Typography style={{"fontFamily": 'Source Code Pro'}}>Sourc MAC</Typography>}/>
                            <FormControlLabel control={<Checkbox defaultChecked sx={{
                                color: 'white',
                                '&.Mui-checked': {
                                    color: 'white',
                                },
                            }}/>} label={<Typography style={{"fontFamily": 'Source Code Pro'}}>Destination
                                MAC</Typography>}/>
                            <FormControlLabel control={<Checkbox defaultChecked sx={{
                                color: 'white',
                                '&.Mui-checked': {
                                    color: 'white',
                                },
                            }}/>} label={<Typography style={{"fontFamily": 'Source Code Pro'}}>Source IP</Typography>}/>
                            <FormControlLabel control={<Checkbox defaultChecked sx={{
                                color: 'white',
                                '&.Mui-checked': {
                                    color: 'white',
                                },
                            }}/>} label={<Typography style={{"fontFamily": 'Source Code Pro'}}>Destination
                                IP</Typography>}/>
                            <FormControlLabel control={<Checkbox defaultChecked sx={{
                                color: 'white',
                                '&.Mui-checked': {
                                    color: 'white',
                                },
                            }}/>} label={<Typography style={{"fontFamily": 'Source Code Pro'}}>Length</Typography>}/>
                            <FormControlLabel control={<Checkbox defaultChecked sx={{
                                color: 'white',
                                '&.Mui-checked': {
                                    color: 'white',
                                },
                            }}/>} label={<Typography style={{"fontFamily": 'Source Code Pro'}}>Info</Typography>}/>
                        </FormGroup>
                        <span className='settingText mgt'>Packets Color</span>
                        <Grid className='colorSettings' container>
                            <Grid item>
                                <Button onClick={onToggleMarkedPicker} className="colorBtn"
                                        style={{"backgroundColor": markedColor}}/>
                                <div style={{"position": "absolute"}}>
                                    {markedVisible && <TwitterPicker className='picker'
                                                                     color={markedColor}
                                                                     onChangeComplete={handleMarkedColor}/>}
                                </div>
                            </Grid>
                            <Grid item>
                                <Typography
                                    style={{"fontFamily": 'Source Code Pro', "color": "white", "marginLeft": "10px"}}>Marked
                                    Packets</Typography>
                            </Grid>
                        </Grid>
                        <Grid className='colorSettings' container>
                            <Grid item>
                                {markedVisible ? "" : <Button onClick={onToggleIgnoredPicker} className="colorBtn"
                                                              style={{"backgroundColor": ignoredColor}}/>}
                                <div style={{"position": "absolute"}}>
                                    {ignoredVisible && <TwitterPicker className='picker'
                                                                      color={ignoredColor}
                                                                      onChangeComplete={handleIgnoredColor}/>}
                                </div>
                            </Grid>
                            <Grid item>
                                <Typography
                                    style={{"fontFamily": 'Source Code Pro', "color": "white", "marginLeft": "10px"}}>Ignored
                                    Packets</Typography>
                            </Grid>
                        </Grid>

                    </Grid>
                </Grid>
            </div>
        </>
    )
}

export default SettingsPanel;