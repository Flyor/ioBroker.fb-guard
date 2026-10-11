![Logo](admin/fb-guard.png)
# ioBroker.fb-guard

[![NPM version](https://img.shields.io/npm/v/iobroker.fb-guard.svg)](https://www.npmjs.com/package/iobroker.fb-guard)
[![Downloads](https://img.shields.io/npm/dm/iobroker.fb-guard.svg)](https://www.npmjs.com/package/iobroker.fb-guard)
![Number of Installations](https://iobroker.live/badges/fb-guard-installed.svg)
![Current version in stable repository](https://iobroker.live/badges/fb-guard-stable.svg)

**Tests:** ![Test and Release](https://github.com/Flyor/ioBroker.fb-guard/workflows/Test%20and%20Release/badge.svg)

Keeps an eye on the security of your [FRITZ!Box](https://fritz.com) and tells you via Telegram or e-mail when something looks wrong.

[German documentation](docs/de/README.md)

## What it checks

- **Failed logins** from the event log, grouped per address, with time, user name, access type and whether it came from the internet or your home network
- **Logins from the internet** that are not on your list of known addresses
- **Open ports**: port forwardings, MyFRITZ, remote access, FTP over the internet, TR-069 and UPnP. Each port comes with a short explanation of what it is usually used for. Ports you opened on purpose can be confirmed once.
- **Firmware**: update available but not installed, automatic updates off
- **Settings**: factory password still active, login without password, two-factor authentication off, new box users, open or weak Wi-Fi encryption, WPS
- **Box restarts** (the event log is cleared on restart)
- A **score from 0 to 100** for your dashboard

The adapter only reads. It never changes anything on the box and only talks to your own box.

## Setup

1. Install the adapter and open the settings. The tabs guide you through it.
2. Create a separate user on the box for the adapter, with only the right "FRITZ!Box Settings" and without internet access.
3. Click "Test connection".
4. Choose Telegram and/or e-mail and send a test message.

All findings are listed in the settings, tab "Findings", each with an explanation. Findings that are intended (for example a port forwarding you set up yourself) can be ticked there and are no longer reported. If anything about them changes, you get notified again. Optionally you get an overview of everything open via Telegram or e-mail, daily or weekly.

## Security and privacy

- The password is stored encrypted in ioBroker and is never written to the log.
- The connection to the box uses TLS. The certificate of the box is remembered on first use, and the adapter stops logging in if it changes.
- After a rejected login the adapter stops trying, so it does not lock you out.
- External services are off by default. Right now there is just one: the firmware comparison with the vendor download server, which only sends the model name.
- The port test only checks your own WAN address.
- Diagnostics mask passwords, keys, user names, addresses and serial numbers.
- Tip: use the ioBroker admin over HTTPS, so your entries are encrypted on the way as well.

No guarantee: this adapter helps you notice problems, it does not make your network secure on its own.

## Disclaimer

FRITZ! and FRITZ!Box are trademarks of FRITZ! GmbH. This project is not affiliated with or endorsed by FRITZ! GmbH (formerly AVM). No guarantee for security, use at your own risk.

## Changelog
<!--
    Placeholder for the next version (at the beginning of the line):
    ### **WORK IN PROGRESS**
-->
### 0.1.1 (2026-10-11)
* (Flyor) Clearer log messages: network problems and internal errors are no longer mixed up
* (Flyor) Pressing "run now" several times no longer queues the same checks again
* (Flyor) Small cleanups in the package

### 0.1.0 (2026-10-11)
* (Flyor) First release: failed logins, open ports, firmware and settings checks, findings and confirmation right in the settings, setup wizard, Telegram and e-mail

## License
MIT License

Copyright (c) 2026 Flyor <AskMe@Stonehiller.de>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
