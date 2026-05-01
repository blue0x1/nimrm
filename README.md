# nimrm

`nimrm` is a native WinRM shell client written in Nim. It provides an interactive PowerShell-oriented remote shell with NTLM, Kerberos, file transfer, in-memory helpers, and practical administration/audit commands.

Author: `blue0x1`  
Version: `1.0.0`

Use only on systems you own or have explicit permission to administer.

## Features

- NTLM authentication with password support.
- NTLM pass-the-hash with `-N/--nt-proof`.
- Kerberos authentication through GSSAPI using `KRB5CCNAME`.
- Kerberos realm override with `-Z/--krb-zone`.
- Kerberos SPN override with `-K/--kerb-spn`.
- HTTP WinRM on port `5985` by default.
- HTTPS/TLS WinRM with `--tls` on port `5986` by default.
- Custom WinRM port with `-p/--port`.
- Interactive PowerShell prompt.
- One-shot command execution with `-c/--command`.
- CMD execution with `!<cmd>`.
- Local command history with arrow-key navigation on POSIX terminals.
- Chunked file upload and download.
- Recursive directory upload and download.
- In-memory local PowerShell script import with `invoke-script`.
- In-memory managed .NET assembly execution with `execute-assembly`.
- AD/domain context reporting with `ad-info`.
- Logging/auditing posture report with `opsec-check`.
- Kerberos encrypted WinRM message wrapping/unwrapping.
- Transport reset/retry handling for common connection failures.
- Single native binary with no Nim package dependencies.

## Requirements

- Nim `>= 1.6.0` to build.
- `libgssapi_krb5.so.2` on Linux or `libgssapi_krb5.dylib` on macOS for Kerberos.
- OpenSSL when building with TLS support using `-d:ssl`.
- Network access to WinRM on the target host.

## Build

```bash
make linux
```

Build with TLS support:

```bash
make ssl
```

Cross-compile for Windows:

```bash
make windows
```

Manual build:

```bash
nim c -d:release --opt:speed -o:nimrm nimrm.nim
```

## Usage

NTLM with password:

```bash
./nimrm -T 192.168.1.10 -A 'CORP\administrator' -P 'Password123'
```

NTLM pass-the-hash:

```bash
./nimrm -T 192.168.1.10 -A 'CORP\user' -N aad3b435b51404eeaad3b435b51404ee:0123456789abcdef0123456789abcdef
```

Kerberos with a ccache:

```bash
KRB5CCNAME=FILE:/tmp/user.ccache ./nimrm -k -T dc01.corp.local -Z CORP.LOCAL
```

Custom port:

```bash
./nimrm -T 192.168.1.10 -A 'CORP\user' -P 'Password123' -p 5985
```

HTTPS/TLS:

```bash
./nimrm -T 192.168.1.10 -A 'CORP\user' -P 'Password123' --tls
```

One-shot command:

```bash
./nimrm -T 192.168.1.10 -A 'CORP\user' -P 'Password123' -c 'whoami'
```

## Options

```text
-T, --target     Target IP or hostname
-A, --account    Username, for example user, user@domain, or DOMAIN\user
-P, --secret     Password for NTLM authentication
-p, --port       WinRM port, default 5985 or 5986 with --tls
-N, --nt-proof   NT hash or LM:NT hash for pass-the-hash
-Z, --krb-zone   Kerberos realm override
-K, --kerb-spn   Kerberos SPN override
-k, --kerb       Use Kerberos authentication
-c, --command    Execute one remote command and exit
--tls            Use HTTPS/TLS
-h, --help       Show help
```

## Interactive Commands

```text
/help                         Show help
exit, quit                    Close shell and exit
!<cmd>                        Run command through cmd.exe
upload <local> [remote]       Upload one file
download <remote> [local]     Download one file
upload-dir <local> [remote]   Recursively upload a directory
download-dir <remote> [local] Recursively download a directory
invoke-script <ps1> [args]    Import a local PowerShell script from memory
execute-assembly <exe> [args] Run a managed .NET assembly from memory
ad-info                       Show AD/domain context through LDAP/.NET
opsec-check                   Show logging and auditing posture
```

## Examples

Run PowerShell:

```powershell
PS> hostname
PS> Get-Process
```

Run CMD:

```powershell
PS> !ipconfig /all
PS> !dir C:\Users
```

Transfer files:

```powershell
PS> upload ./tool.exe C:\Temp\tool.exe
PS> download C:\Temp\out.txt ./out.txt
```

Transfer directories:

```powershell
PS> upload-dir ./payloads C:\Temp\payloads
PS> download-dir C:\Temp\logs ./logs
```

Import a local PowerShell script into the current remote session:

```powershell
PS> invoke-script ./AdminTools.ps1
PS> Get-Command
```

Run a managed .NET assembly from memory:

```powershell
PS> execute-assembly ./tool.exe arg1 arg2
```

Show AD context:

```powershell
PS> ad-info
```

Show logging and auditing posture:

```powershell
PS> opsec-check
```

## Notes

- `execute-assembly` supports managed .NET assemblies. Native unmanaged PE loading is not implemented.
- `invoke-script` imports the script into the current remote runspace so functions remain available after import.
- `ad-info` and `opsec-check` are read-only reporting commands.
- Some event log, Defender, and AD queries require sufficient privileges on the remote host.

## License

MIT
