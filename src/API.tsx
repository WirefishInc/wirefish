import {invoke} from '@tauri-apps/api';

async function startSniffing() {
    return invoke('start_sniffing')
}

async function stopSniffing() {
    return invoke('stop_sniffing')
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

const API = {
    startSniffing,
    stopSniffing,
    getInterfacesList,
    selectInterface,
    generateReport
};

export default API;
