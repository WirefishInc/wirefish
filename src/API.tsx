import {invoke} from '@tauri-apps/api';
import {GeneralPacket} from "./types/sniffing";

async function startSniffing(isResume: boolean) {
    return invoke('start_sniffing', {isResume})
}

async function stopSniffing(stop: boolean) {
    return invoke('stop_sniffing', {stop})
}

async function selectInterface(interfaceName: string) {
    return invoke('select_interface', {interfaceName})
}

async function getInterfacesList(): Promise<string[]> {
    return invoke('get_interfaces_list')
}

async function generateReport(reportPath: string, firstGeneration: boolean): Promise<boolean> {
    return invoke('generate_report', {reportPath, firstGeneration})
}

async function getPackets(start: number, end: number, filtersType: any[], filtersValue: any[]): Promise<GeneralPacket[]> {
    return invoke('get_packets', {start, end, filtersType, filtersValue})
}

const API = {
    startSniffing,
    stopSniffing,
    getInterfacesList,
    selectInterface,
    generateReport,
    getPackets
};

export default API;
