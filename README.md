<h1 align="center">nimrm</h1>

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
  <b><span style="color:#2f81f7">NTLM</span></b> ·
  <b><span style="color:#a371f7">Kerberos</span></b> ·
  <b><span style="color:#3fb950">PowerShell</span></b> ·
  <b><span style="color:#d29922">File Transfer</span></b> ·
  <b><span style="color:#f85149">In-Memory Helpers</span></b>
</p>

---

## Legal Notice

`nimrm` is intended for lawful administration, security testing, and research on systems you own or have explicit permission to access. The author is not responsible for misuse or damage caused by this tool.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Build](#build)
- [Usage](#usage)
- [Options](#options)
- [Interactive Commands](#interactive-commands)
- [Examples](#examples)
- [Notes](#notes)
- [License](#license)

## Overview

`nimrm` provides a compact WinRM shell with practical authentication, command execution, transfer, and reporting helpers. It is built as a native Nim binary with no Nim package dependencies.

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
