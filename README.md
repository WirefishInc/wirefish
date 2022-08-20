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



## Project summary
The project aims at building a multiplatform application capable of intercepting incoming
and outgoing traffic through the network interfaces of a computer. The application will set
the network adapter in promiscuous mode, collect IP address, port and protocol type of
observed traffic and will generate a textual report describing a synthesis of the observed
events.

Such a report should list for each of the network address/port pairs that have been
observed, the protocols that was transported, the cumulated number of bytes transmitted,
the timestamp of the first and last occurrence of information exchange.

Command line parameters will be used to specify the network adapter to be inspected, the
output file to be generated, the interval after which a new report is to be generated, or a
possible filter to apply to captured data.

## Problem Definition
The system to be designed consists of a multi-platform library that supports network data
capturing and recording, and a sample application that gives access to it.

The library will be properly documented, providing a clear definition of its intended usage,
as well as of any error condition that can be reported.

By using the sample application, the user will be able to
- define the network adapter to be sniffed
- select a time interval after which an updated version of the report will be generated
- temporarily pause and subsequently resume the sniffing process
- define the file that will contain the report

The application should also take care to properly indicate any failure of the sniffing
process, providing meaningful and actionable feedback.
When the sniffing process is active, a suitable indication should be provided to the user.