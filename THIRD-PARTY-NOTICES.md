# Third-party software in Keytap

| Component | Licence | Use |
|-----------|---------|-----|
| Qt 6 / PySide6 | LGPL-3.0 | windows, the tray icon, drawing |
| Bitwarden CLI (bw-oss build) | GPL-3.0 | reading your Bitwarden vault |
| comtypes | MIT | UI Automation, for spotting login boxes |

The Bitwarden CLI is not linked into Keytap: it is Bitwarden's own program in
`tools\bw\bw.exe`, run as a command. It is the open-source build, which has no
Bitwarden-licensed code in it, downloaded unchanged from
https://github.com/bitwarden/clients/releases (the `cli-v…` releases). Its
source is in the same repository, under `apps/cli`.

Keytap is not made by or affiliated with Bitwarden, Inc. Bitwarden is a
trademark of Bitwarden, Inc.
