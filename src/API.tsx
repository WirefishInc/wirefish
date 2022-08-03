import { invoke } from '@tauri-apps/api';

async function startSniffing() { invoke('start_sniffing') };
async function stopSniffing() { invoke('stop_sniffing') };
async function selectInterface(interfaceName: string) { invoke('select_interface', {interfaceName}) };
async function getInterfacesList(): Promise<string[]> { return invoke('get_interfaces_list') };

const API = { startSniffing, stopSniffing, getInterfacesList, selectInterface };
export default API;
