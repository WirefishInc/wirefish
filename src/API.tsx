import {invoke} from '@tauri-apps/api';

async function startSniffing(reportPath: string, reportInterval: number) {
    return invoke('start_sniffing', {reportPath, reportInterval})
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

const API = {
    startSniffing,
    stopSniffing,
    getInterfacesList,
    selectInterface
};

export default API;
