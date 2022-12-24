import * as React from 'react';
import {FiletypeCsv, Wifi} from 'react-bootstrap-icons';
import './custom.css'

interface SessionProps {
    csv: boolean
}

const SessionCard: React.FC<SessionProps> = ({csv}) => {
    return (
        <div className='session'>
            <div className={csv ? 'icon-background-csv' : 'icon-background-no-csv'}>
                <div className='icon-container'>
                    {csv ? <FiletypeCsv className='icon csv'/> : <Wifi className='icon no-csv'/>}
                </div>
                <div className='info-container'>
                    <span className={csv ? 'csv session-name' : 'no-csv session-name'}>Session 1</span>
                    <span className='session-info'>Total packets sniffed: 1278</span>
                    <span className='session-info'>Total bytes sniffed: 45937 MB</span>
                    <span className='session-date'>2022-02-02 12:34:55</span>
                </div>
            </div>
        </div>
    )
}

export default SessionCard;