# PoC - Sniffer
Run it with `npm run tauri dev`

## Prerequisites

### Windows
Install WinPcap.
Download the WinPcap Developer's Pack. Add the `/Lib` or `/Lib/x64` folder to your `LIB` environment variable.

### Linux
On Debian based Linux, install `libpcap-dev`. If not running as root, you need to set capabilities like so: sudo setcap cap_net_raw,cap_net_admin=eip path/to/bin

### Mac OS X
`libpcap` should be installed on Mac OS X by default.