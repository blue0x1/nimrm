<h1 align="center">nimrm</h1>

<p align="center">
  <a href="https://github.com/blue0x1/nimrm/releases"><img src="https://img.shields.io/github/v/release/blue0x1/nimrm" alt="Release"></a>
  <a href="https://github.com/blue0x1/nimrm/releases"><img src="https://img.shields.io/github/downloads/blue0x1/nimrm/total.svg" alt="Downloads"></a>
</p>

<p align="center">
  <b>Native WinRM shell client written in Nim</b>
</p>

<p align="center">
  <sub>
    <b>Version</b> 1.0.0 ·
    <b>Author</b> Chokri Hammedi (blue0x1) ·
    <b>License</b> MIT
  </sub>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/NTLM-08f5f9?style=for-the-badge" alt="NTLM">
  <img src="https://img.shields.io/badge/Kerberos-fc1383?style=for-the-badge" alt="Kerberos">
  <img src="https://img.shields.io/badge/PowerShell-08f5f9?style=for-the-badge" alt="PowerShell">
  <img src="https://img.shields.io/badge/File%20Transfer-fc1383?style=for-the-badge" alt="File Transfer">
  <img src="https://img.shields.io/badge/In--Memory-08f5f9?style=for-the-badge" alt="In-Memory Helpers">
  <img src="https://img.shields.io/badge/Multi--Session-fc1383?style=for-the-badge" alt="Multi-Session">
</p>

<p align="center">
  <a href="https://github.com/blue0x1/nimrm/wiki"><img src="https://img.shields.io/badge/Documentation-08f5f9?style=for-the-badge&logo=gitbook&logoColor=black" alt="Documentation"></a>
  <a href="https://github.com/blue0x1/nim-winrm"><img src="https://img.shields.io/badge/WinRM%20Library-fc1383?style=for-the-badge&logo=nim&logoColor=white" alt="WinRM Library"></a>
</p>

---
<img width="1024" height="595" alt="image" src="https://github.com/user-attachments/assets/ee35bbe2-9d5b-4b98-9bf8-78e3286a1219" />


## Legal Notice

`nimrm` is intended for lawful administration, security testing, and research on systems you own or have explicit permission to access. The author is not responsible for misuse or damage caused by this tool.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Build](#build)
- [Performance](#performance)
- [Usage](#usage)
- [Options](#options)
- [Interactive Commands](#interactive-commands)
- [Session Management](#session-management)
- [Examples](#examples)
- [Notes](#notes)
- [License](#license)

## Overview

`nimrm` provides a compact and fast WinRM shell with practical authentication, command execution, transfer, and reporting helpers. It is built as a native Nim binary with no Nim package dependencies.

## Features

| Area | Support |
| --- | --- |
| Authentication | NTLM password, NTLM hash, Kerberos via `KRB5CCNAME` |
| WinRM transport | HTTP, HTTPS/TLS, custom port |
| Shell | Interactive PowerShell, CMD prefix, one-shot command mode |
| Transfers | File upload/download, recursive directory transfer |
| In-memory | PowerShell script import, managed .NET assembly execution |
| Reporting | AD/domain context, logging and auditing posture |
| Reliability | Kerberos message wrapping, transport reset/retry handling |

## Requirements

| Component | Requirement |
| --- | --- |
| Build | Nim `>= 1.6.0` |
| Kerberos | `libgssapi_krb5.so.2` on Linux or `libgssapi_krb5.dylib` on macOS |
| TLS build | OpenSSL and `-d:ssl` |
| Target | WinRM reachable on the selected port |

## Installation

Nimble:

```bash
nimble install nimrm
```

Download the latest release:

```bash
curl -L -o nimrm https://github.com/blue0x1/nimrm/releases/latest/download/nimrm
chmod +x nimrm
```

Windows release binary:

```powershell
Invoke-WebRequest -Uri https://github.com/blue0x1/nimrm/releases/latest/download/nimrm.exe -OutFile nimrm.exe
```

Debian package:

```bash
curl -L -o nimrm_1.0.0_amd64.deb https://github.com/blue0x1/nimrm/releases/latest/download/nimrm_1.0.0_amd64.deb
sudo dpkg -i nimrm_1.0.0_amd64.deb
```

Build from source:

```bash
git clone https://github.com/blue0x1/nimrm.git
cd nimrm
make linux
```

## Build

```bash
make linux
```

```bash
make ssl
```

```bash
make windows
```

Manual build:

```bash
nim c -d:release --opt:speed -o:nimrm nimrm.nim
```

## Performance

`nimrm` is designed to stay fast by using a native Nim binary, persistent WinRM runspace, chunked transfer logic, and compact progress rendering.

| Operation | Implementation |
| --- | --- |
| Upload | Chunked Base64 writes with adaptive retry on large envelopes |
| Download | Streamed Base64 chunks with progress tracking |
| Directory transfer | Recursive file enumeration using the same chunked transfer path |
| Command execution | Reuses the active WinRM shell/runspace instead of reconnecting per command |

## Usage

NTLM password:

```bash
./nimrm -T 192.168.1.10 -A 'CORP\administrator' -P 'Password123'
```

NTLM pass-the-hash:

```bash
./nimrm -T 192.168.1.10 -A 'CORP\user' -N aad3b435b51404eeaad3b435b51404ee:0123456789abcdef0123456789abcdef
```

Kerberos:

```bash
KRB5CCNAME=FILE:/tmp/user.ccache ./nimrm -k -T dc01.corp.local -Z CORP.LOCAL
```

Force NTLM message encryption over HTTP:

```bash
./nimrm -T 192.168.1.10 -A 'CORP\user' -P 'Password123' --seal
```

Custom port:

```bash
./nimrm -T 192.168.1.10 -A 'CORP\user' -P 'Password123' -p 5985
```

One-shot command:

```bash
./nimrm -T 192.168.1.10 -A 'CORP\user' -P 'Password123' -c 'whoami'
```

## Options

| Option | Description |
| --- | --- |
| `-T`, `--target` | Target IP or hostname |
| `-A`, `--account` | Username: `user`, `user@domain`, or `DOMAIN\user` |
| `-P`, `--secret` | NTLM password |
| `-p`, `--port` | WinRM port |
| `-N`, `--nt-proof` | NT hash or `LM:NT` hash |
| `-Z`, `--krb-zone` | Kerberos realm override |
| `-K`, `--kerb-spn` | Kerberos SPN override |
| `-k`, `--kerb` | Use Kerberos authentication |
| `-c`, `--command` | Execute one command and exit |
| `--tls` | Use HTTPS/TLS |
| `-h`, `--help` | Show help |

## Interactive Commands

| Command | Description |
| --- | --- |
| `/help` | Show help |
| `exit`, `quit` | Close shell |
| `!<cmd>` | Run through `cmd.exe` |
| `upload <local> [remote]` | Upload one file |
| `download <remote> [local]` | Download one file |
| `upload-dir <local> [remote]` | Upload a directory |
| `download-dir <remote> [local]` | Download a directory |
| `invoke-script <ps1> [args]` | Import local PowerShell from memory |
| `execute-assembly <exe> [args]` | Run managed .NET from memory |
| `ad-info` | Show AD/domain context |
| `opsec-check` | Show logging and auditing posture |
| `sessions` | List all active sessions |
| `session <opts>` | Create a new session |
| `use <name\|id>` | Switch to a session |
| `kill <name\|id>` | Close and remove a session |

## Session Management

nimrm supports multiple concurrent WinRM sessions. You can pivot between different hosts and users without leaving the shell.

Create a new session from inside an existing one:

```powershell
PS C:\Users\Administrator> session -T 10.0.0.5 -A 'CORP\user2' -P 'Pass123'
PS C:\Users\Administrator> session -T dc02.corp.local -A user@corp.local -N aad3b435:0123456789abcdef -n dc02
PS C:\Users\Administrator> session -T dc03.corp.local -k -Z CORP.LOCAL -n dc03
```

List active sessions:

```
PS C:\Users\Administrator> sessions

  ID  Name              Target                    User              Auth
  --  ----              ------                    ----              ----
 * 1  session-1         dc01.corp.local:5985      administrator     Kerberos
   2  session-2         10.0.0.5:5985             user2             NTLM
   3  dc02              dc02.corp.local:5985      user              NTLM
```

Switch between sessions:

```powershell
[session-2] PS C:\Users\user2> use 1
[*] Switched to session: session-1 (dc01.corp.local:5985)
[session-1] PS C:\Users\Administrator> use dc02
[*] Switched to session: dc02 (dc02.corp.local:5985)
```

Close a session:

```powershell
[dc02] PS C:\Users\user> kill 2
[*] Killed session: session-2
```

Session options:

| Option | Description |
| --- | --- |
| `-T` | Target host |
| `-A` | Username |
| `-P` | Password |
| `-N` | NT hash |
| `-k` | Kerberos auth |
| `-Z` | Kerberos realm |
| `-K` | SPN override |
| `-p` | Port |
| `--tls` | Use HTTPS |
| `-n` | Custom session name |

## Examples

PowerShell and CMD:

```powershell
PS> hostname
PS> Get-Process
PS> !ipconfig /all
```

Transfers:

```powershell
PS> upload ./tool.exe C:\Temp\tool.exe
PS> download C:\Temp\out.txt ./out.txt
PS> upload-dir ./payloads C:\Temp\payloads
PS> download-dir C:\Temp\logs ./logs
```

In-memory helpers:

```powershell
PS> invoke-script ./AdminTools.ps1
PS> execute-assembly ./tool.exe arg1 arg2
```

Reporting:

```powershell
PS> ad-info
PS> opsec-check
```

## Notes

- `execute-assembly` supports managed .NET assemblies only.
- `invoke-script` imports into the current remote runspace.
- `ad-info` and `opsec-check` are read-only reporting commands.
- Some reporting data requires sufficient remote privileges.

## License

MIT. See [LICENSE](LICENSE).
