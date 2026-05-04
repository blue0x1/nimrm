## nimrm.nim
## Interactive WinRM Shell Client for Nim
## Author: Chokri Hammedi (blue0x1)
## Version: 1.0.0
## Compile: nim c -d:release -d:ssl nimrm.nim
##
## Legal notice:
##   nimrm is intended for lawful administration, security testing, and
##   research on systems you own or have explicit permission to access.
##   The author is not responsible for misuse or damage caused by this tool.
##
## Features:
##   - NTLM authentication (manual implementation with NTLMv2)
##   - Kerberos/GSSAPI authentication (via C FFI to libgssapi_krb5)
##   - Interactive PS> prompt with UTF-16LE Base64 PowerShell encoding
##   - CMD prefix with '!'
##   - upload/download built-ins
##   - SSL support

import std/[
  strutils, strformat, base64, os,
  parseopt, terminal, times, random
]

import winrm

type
  Session = ref object
    name: string
    client: WinRMClient
    currentPath: string
    host: string
    user: string
    authStr: string
    connected: bool

const
  DownloadChunkSize = 524288
  DownloadBinaryChunkSize = 65536
  DownloadLineChars = 32768
  PsrpDownloadChunkSize = 196608
  PsrpUploadChunkSize = PsrpDownloadChunkSize
  PsrpDownloadLineChars = 4096
  InMemoryB64ChunkSize = 196608

proc psQuote(s: string): string =
  "'" & s.replace("'", "''") & "'"

proc cwdPrefix(c: WinRMClient): string =
  if c.remoteCwd != "": "Set-Location " & psQuote(c.remoteCwd) & "; " else: ""

proc shellSplit(s: string): seq[string] =
  var cur: string
  var quote = '\0'
  for ch in s:
    if quote != '\0':
      if ch == quote:
        quote = '\0'
      else:
        cur.add ch
    elif ch in {'"', '\''}:
      quote = ch
    elif ch in {' ', '\t'}:
      if cur.len > 0:
        result.add cur
        cur = ""
    else:
      cur.add ch
  if cur.len > 0:
    result.add cur

proc remotePathSetup(varName, pathArg, defaultName: string): string =
  if pathArg == "":
    return "$" & varName & " = Join-Path -Path (Get-Location).Path -ChildPath " & psQuote(defaultName) & "; "
  if pathArg.endsWith("\\") or pathArg.endsWith("/"):
    return "$" & varName & " = Join-Path -Path " & psQuote(pathArg) & " -ChildPath " & psQuote(defaultName) & "; " &
           "if(-not [IO.Path]::IsPathRooted($" & varName & ")){$" & varName & " = Join-Path -Path (Get-Location).Path -ChildPath $" & varName & "}; "
  result = "$" & varName & " = " & psQuote(pathArg) & "; " &
           "if(-not [IO.Path]::IsPathRooted($" & varName & ")){$" & varName & " = Join-Path -Path (Get-Location).Path -ChildPath $" & varName & "}; "

proc remoteBaseName(pathArg: string): string =
  var p = pathArg.strip().replace("\\", "/")
  while p.endsWith("/") and p.len > 1:
    p.setLen(p.len - 1)
  let idx = p.rfind("/")
  if idx >= 0 and idx + 1 < p.len:
    result = p[idx + 1..^1]
  else:
    result = p
  if result == "": result = "download.bin"

proc localDownloadPath(remoteArg, localArg: string): string =
  let name = remoteBaseName(remoteArg)
  if localArg == "":
    return getCurrentDir() / name
  if dirExists(localArg):
    return localArg / name
  result = localArg

proc remoteDisplayPwd(c: WinRMClient): string =
  if c.remoteCwd != "": c.remoteCwd else: "remote current directory"

proc isAuthFailure(e: ref Exception): bool =
  result = e of WinRMAuthorizationError

proc resolveRemoteFile(c: var WinRMClient, setup, requested: string): tuple[path: string, size: int] =
  let probe = setup &
    "if(Test-Path -LiteralPath $p -PathType Leaf){" &
    "$item = Get-Item -LiteralPath $p; 'OK|' + $item.FullName + '|' + $item.Length" &
    "}else{'NF|' + $p}"
  let probeOut = runCmdFastCached(c, probe, false).strip()
  for rawLine in probeOut.splitLines():
    let line = rawLine.strip()
    if line.startsWith("OK|"):
      let parts = line.split('|')
      if parts.len >= 3:
        try:
          return (parts[1], parseInt(parts[2]))
        except:
          discard
    elif line.startsWith("NF|"):
      let p = line[3..^1]
      raise newException(IOError, "remote file not found: " & requested & " in " & remoteDisplayPwd(c) & " (" & p & ")")
  raise newException(IOError, "could not resolve remote file: " & requested & " in " & remoteDisplayPwd(c))

proc resolveRemoteDir(c: var WinRMClient, setup, requested: string): string =
  let probe = setup &
    "if(Test-Path -LiteralPath $p -PathType Container){" &
    "'OK|' + (Resolve-Path -LiteralPath $p).Path" &
    "}else{'NF|' + $p}"
  let probeOut = runCmdFastCached(c, probe, false).strip()
  for rawLine in probeOut.splitLines():
    let line = rawLine.strip()
    if line.startsWith("OK|"):
      return line[3..^1]
    elif line.startsWith("NF|"):
      let p = line[3..^1]
      raise newException(IOError, "remote directory not found: " & requested & " in " & remoteDisplayPwd(c) & " (" & p & ")")
  raise newException(IOError, "could not resolve remote directory: " & requested & " in " & remoteDisplayPwd(c))

proc remoteJoin(root, rel: string): string =
  var r = root.strip()
  while r.endsWith("\\") or r.endsWith("/"):
    r.setLen(r.len - 1)
  var child = rel.replace("/", "\\")
  while child.startsWith("\\") or child.startsWith("/"):
    child = child[1..^1]
  if r == "":
    result = child
  elif child == "":
    result = r
  else:
    result = r & "\\" & child

proc localJoinRel(root, rel: string): string =
  var path = root
  for part in rel.replace("\\", "/").split('/'):
    if part.len > 0:
      path = path / part
  result = path

proc collectLocalTree(root: string, dirs, files: var seq[string]) =
  for kind, path in walkDir(root):
    case kind
    of pcDir:
      dirs.add path
      collectLocalTree(path, dirs, files)
    of pcFile:
      files.add path
    else:
      discard

proc localRelPath(path, root: string): string =
  var base = root
  while base.endsWith(DirSep):
    base.setLen(base.len - 1)
  let prefix = base & $DirSep
  if path.startsWith(prefix):
    result = path[prefix.len..^1]
  else:
    result = extractFilename(path)

proc drawProgress(label: string, current, total: int) =
  const spinFrames = ["⣾","⣽","⣻","⢿","⡿","⣟","⣯","⣷"]
  const barWidth   = 34

  var spinIdx {.global.}: int   = 0
  var t0      {.global.}: float = 0.0

  if current == 0:
    t0      = epochTime()
    spinIdx = 0

  let elapsed = max(epochTime() - t0, 0.001)
  let pct     = if total > 0: (current * 100) div total else: 100
  let nFill   = if total > 0: (current * barWidth) div total else: barWidth
  let done    = current >= total

  proc fmtBytes(b: int): string =
    if b < 1024:      $b & " B"
    elif b < 1048576: formatFloat(b.float / 1024.0,    ffDecimal, 1) & " KB"
    else:             formatFloat(b.float / 1048576.0, ffDecimal, 2) & " MB"

  let spin = if done: "\e[1;33m✔\e[0m"
             else: "\e[36m" & spinFrames[spinIdx mod spinFrames.len] & "\e[0m"
  inc spinIdx

  var bar = ""
  for i in 0..<barWidth:
    if i < nFill:                 bar.add("\e[36m━")
    elif i == nFill and not done: bar.add("\e[33m╸")
    else:                         bar.add("\e[90m╌")
  bar.add("\e[0m")

  let pctStr = (if done: "\e[1;33m" else: "\e[33m") & align($pct & "%", 4) & "\e[0m"

  let sizeStr = "\e[37m" & fmtBytes(current) & "\e[90m/\e[37m" & fmtBytes(total) & "\e[0m"

  var extras = ""
  if done:
    extras = "  \e[90mdone in \e[33m" & formatFloat(elapsed, ffDecimal, 1) & "s\e[0m"
  elif elapsed > 0.3 and current > 0:
    let bps = current.float / elapsed
    extras = "  \e[33m" & fmtBytes(int(bps)) & "/s\e[0m"
    let eta = int((total - current).float / bps)
    if eta > 0:
      extras.add("  \e[90meta \e[37m" & $eta & "s\e[0m")

  stdout.write("\r\e[K" &
    spin & "  \e[1;37m" & label & "\e[0m  " &
    "\e[90m[\e[0m" & bar & "\e[90m]\e[0m  " &
    pctStr & "  " & sizeStr & extras)
  stdout.flushFile()

proc statusLine(color: ForegroundColor, msg: string) =
  stdout.write("\r\e[K")
  stdout.flushFile()
  styledEcho(color, msg)

proc uploadFile(c: var WinRMClient, args: seq[string]) =
  if args.len < 1 or args.len > 2:
    raise newException(ValueError, "usage: upload <local-file> [remote-file-or-dir]")
  let localPath = if isAbsolute(args[0]): args[0] else: getCurrentDir() / args[0]
  if not fileExists(localPath):
    raise newException(IOError, "local file not found: " & args[0] & " in " & getCurrentDir() & " (" & localPath & ")")

  let fileName = extractFilename(localPath)
  let remoteArg = if args.len == 2: args[1] else: ""
  let data = readFile(localPath)
  let setup = cwdPrefix(c) & remotePathSetup("p", remoteArg, fileName)

  var off = 0
  var chunkSize = PsrpUploadChunkSize
  var uploadedLenCheck = ""
  if data.len <= 1024:
    drawProgress("upload", 0, data.len)
    let b64 = encode(data)
    let cmd = setup & "$dir = Split-Path -Parent $p; " &
              "if($dir -and -not (Test-Path -LiteralPath $dir)){New-Item -ItemType Directory -Path $dir -Force | Out-Null}; " &
              "$bytes = [Convert]::FromBase64String(" & psQuote(b64) & "); " &
              "[IO.File]::WriteAllBytes($p, $bytes); " &
              "(Get-Item -LiteralPath $p).Length"
    uploadedLenCheck = runCmdFastOrPsrp(c, cmd).strip()
    off = data.len
    drawProgress("upload", off, data.len)
  else:
    try:
      if c.cmdShellDenied:
        raise newException(IOError, "WinRS stream unavailable for this session")
      statusLine(fgWhite, "[*] Upload mode: WinRS stream")
      uploadFileStream(c, data, setup, data.len)
    except Exception as e:
      if getEnv("WINRMSHELL_DEBUG") == "1":
        statusLine(fgYellow, "[debug] streaming upload failed: " & e.msg)
      let msg = e.msg.toLowerAscii()
      if "access is denied" in msg or "could not find shellid" in msg or
         "winrm error 500" in msg or "not supported" in msg or
         "wsman" in msg:
        c.cmdShellDenied = true
      elif not c.cmdShellDenied:
        raise
      statusLine(fgYellow, "[*] Upload mode: PSRP chunks")
      drawProgress("upload-init", 0, data.len)
      ensureShell(c, true)
      let varName = "wrm_upload_" & genUuid().replace("-", "")
      let b64Data = encode(data)
      discard runCmdFastCached(c, "$script:" & varName & " = New-Object System.Text.StringBuilder", false)
      drawProgress("upload", 0, data.len)
      chunkSize = InMemoryB64ChunkSize
      off = 0
      while off < data.len:
        let startB64 = (off div 3) * 4
        let stopB64 = min(startB64 + chunkSize, b64Data.len)
        let cmd = "[void]$script:" & varName & ".Append(" & psQuote(b64Data[startB64 ..< stopB64]) & ")"
        try:
          discard runCmdFastCached(c, cmd, false)
        except Exception as e:
          let msg = e.msg.toLowerAscii()
          if ("413" in msg or "envelope" in msg or "too large" in msg or "exceed" in msg) and chunkSize > 131072:
            resetTransport(c)
            ensureShell(c, true)
            chunkSize = 131072
            continue
          raise
        off = min((stopB64 div 4) * 3, data.len)
        drawProgress("upload", off, data.len)
      uploadedLenCheck = runCmdFastCached(c, setup &
        "$dir = Split-Path -Parent $p; " &
        "if($dir -and -not (Test-Path -LiteralPath $dir)){New-Item -ItemType Directory -Path $dir -Force | Out-Null}; " &
        "$b64 = $script:" & varName & ".ToString(); " &
        "$script:" & varName & " = $null; " &
        "$bytes = [Convert]::FromBase64String($b64); " &
        "$b64 = $null; " &
        "[IO.File]::WriteAllBytes($p, $bytes); " &
        "$bytes = $null; [GC]::Collect(); " &
        "(Get-Item -LiteralPath $p).Length", false).strip()
      off = data.len
      drawProgress("upload", off, data.len)

  echo ""
  let sizeCheck =
    if uploadedLenCheck != "":
      uploadedLenCheck
    else:
      runCmdFastOrPsrp(c, setup & "(Get-Item -LiteralPath $p).Length").strip()
  if sizeCheck != $data.len:
    raise newException(IOError, "remote upload size mismatch: expected " & $data.len & " bytes, got " & sizeCheck)
  styledEcho(fgGreen, "[+] Uploaded " & $data.len & " bytes from " & localPath)

proc uploadDir(c: var WinRMClient, args: seq[string]) =
  if args.len < 1 or args.len > 2:
    raise newException(ValueError, "usage: upload-dir <local-dir> [remote-dir]")
  let localRoot = absolutePath(if isAbsolute(args[0]): args[0] else: getCurrentDir() / args[0])
  if not dirExists(localRoot):
    raise newException(IOError, "local directory not found: " & args[0] & " in " & getCurrentDir() & " (" & localRoot & ")")

  let remoteRoot = if args.len == 2: args[1] else: extractFilename(localRoot)
  var dirs, files: seq[string]
  collectLocalTree(localRoot, dirs, files)

  discard runCmdFastOrPsrp(c, cwdPrefix(c) & remotePathSetup("root", remoteRoot, extractFilename(localRoot)) &
                    "if(-not (Test-Path -LiteralPath $root)){New-Item -ItemType Directory -Path $root -Force | Out-Null}")

  for d in dirs:
    let rel = localRelPath(d, localRoot)
    let remoteDir = remoteJoin(remoteRoot, rel)
    discard runCmdFastOrPsrp(c, cwdPrefix(c) & remotePathSetup("d", remoteDir, "") &
                      "if(-not (Test-Path -LiteralPath $d)){New-Item -ItemType Directory -Path $d -Force | Out-Null}")

  var done = 0
  for f in files:
    inc done
    let rel = localRelPath(f, localRoot)
    styledEcho(fgYellow, fmt"[*] upload-dir [{done}/{files.len}] {rel}")
    uploadFile(c, @[f, remoteJoin(remoteRoot, rel)])

  styledEcho(fgGreen, fmt"[+] Uploaded directory {localRoot} ({files.len} files, {dirs.len} dirs)")

proc remoteExecPath(pathArg: string): string =
  if pathArg.startsWith(".\\") or pathArg.startsWith("./") or pathArg.contains("\\") or pathArg.contains("/"):
    result = pathArg
  else:
    result = ".\\" & pathArg

proc psArray(args: seq[string]): string =
  result = "@("
  for i, a in args:
    if i > 0: result.add ","
    result.add psQuote(a)
  result.add ")"

proc invokeScript(c: var WinRMClient, args: seq[string]) =
  if args.len < 1:
    raise newException(ValueError, "usage: invoke-script <local-ps1> [args...]")

  let scriptPath = if isAbsolute(args[0]): args[0] else: getCurrentDir() / args[0]
  if not fileExists(scriptPath):
    raise newException(IOError, "local script not found: " & scriptPath)

  let scriptText = readFile(scriptPath)
  let b64 = encode(scriptText)
  let varName = "wrm_script_" & genUuid().replace("-", "")
  let runArgs = if args.len > 1: args[1..^1] else: @[]

  drawProgress("stage-script", 0, b64.len)
  if b64.len <= 350000:
    let cmd =
      "$ErrorActionPreference = 'Stop'; " &
      "$argv = " & psArray(runArgs) & "; " &
      "$bytes = [Convert]::FromBase64String(" & psQuote(b64) & "); " &
      "if($bytes.Length -ge 2 -and $bytes[0] -eq 0xff -and $bytes[1] -eq 0xfe){$scriptText = [Text.Encoding]::Unicode.GetString($bytes)} " &
      "elseif($bytes.Length -ge 2 -and $bytes[0] -eq 0xfe -and $bytes[1] -eq 0xff){$scriptText = [Text.Encoding]::BigEndianUnicode.GetString($bytes)} " &
      "else{$scriptText = [Text.Encoding]::UTF8.GetString($bytes)}; " &
      "$bytes = $null; " &
      "$sb = [ScriptBlock]::Create($scriptText); " &
      "$scriptText = $null; " &
      ". $sb @argv *>&1"
    let output = runCmdFast(c, cmd, false)
    drawProgress("stage-script", b64.len, b64.len)
    echo ""
    if output.len > 0:
      stdout.write(output)
      if not output.endsWith("\n"):
        stdout.write("\n")
      stdout.flushFile()
    return

  ensureShell(c)
  discard runCmd(c, "$script:" & varName & " = New-Object System.Text.StringBuilder", false)
  var off = 0
  try:
    while off < b64.len:
      let stop = min(off + InMemoryB64ChunkSize, b64.len)
      discard runCmd(c, "[void]$script:" & varName & ".Append(" & psQuote(b64[off ..< stop]) & ")", false)
      off = stop
      drawProgress("stage-script", off, b64.len)
    echo ""

    let cmd =
      "$ErrorActionPreference = 'Stop'; " &
      "$argv = " & psArray(runArgs) & "; " &
      "$b64 = $script:" & varName & ".ToString(); " &
      "$script:" & varName & " = $null; " &
      "$bytes = [Convert]::FromBase64String($b64); " &
      "$b64 = $null; " &
      "if($bytes.Length -ge 2 -and $bytes[0] -eq 0xff -and $bytes[1] -eq 0xfe){$scriptText = [Text.Encoding]::Unicode.GetString($bytes)} " &
      "elseif($bytes.Length -ge 2 -and $bytes[0] -eq 0xfe -and $bytes[1] -eq 0xff){$scriptText = [Text.Encoding]::BigEndianUnicode.GetString($bytes)} " &
      "else{$scriptText = [Text.Encoding]::UTF8.GetString($bytes)}; " &
      "$bytes = $null; " &
      "$sb = [ScriptBlock]::Create($scriptText); " &
      "$scriptText = $null; " &
      ". $sb @argv *>&1"

    let output = runCmd(c, cmd, false)
    if output.len > 0:
      stdout.write(output)
      if not output.endsWith("\n"):
        stdout.write("\n")
      stdout.flushFile()
  finally:
    try:
      discard runCmd(c, "$script:" & varName & " = $null; [GC]::Collect()", false)
    except:
      discard

proc adInfo(c: var WinRMClient) =
  let cmd = """
$ErrorActionPreference = 'Continue'
function V($v){
  if($null -eq $v){ return $null }
  if($v -is [System.DirectoryServices.PropertyValueCollection]){
    if($v.Count -eq 0){ return $null }
    return (@($v) | ForEach-Object { $_.ToString() }) -join ', '
  }
  if($v -is [array]){
    return ($v | ForEach-Object { $_.ToString() }) -join ', '
  }
  return $v.ToString()
}
function W($k,$v){ $s = V $v; if($null -ne $s -and $s.Length -gt 0){ "{0,-24} {1}" -f ($k + ':'), $s } }
try {
  $root = [ADSI]'LDAP://RootDSE'
  W 'Default naming ctx' $root.defaultNamingContext
  W 'Configuration ctx' $root.configurationNamingContext
  W 'Schema ctx' $root.schemaNamingContext
  W 'DNS host' $root.dnsHostName
  W 'Domain controller' $root.serverName
  W 'Domain functional' $root.domainFunctionality
  W 'Forest functional' $root.forestFunctionality
  W 'DC functional' $root.domainControllerFunctionality
} catch {
  W 'LDAP RootDSE' $_.Exception.Message
}
try {
  $dom = [DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()
  W 'Domain name' $dom.Name
  W 'NetBIOS name' $dom.NetBiosName
  W 'Forest' $dom.Forest.Name
  W 'PDC role owner' $dom.PdcRoleOwner.Name
  ''
  'Domain controllers:'
  $dom.DomainControllers | ForEach-Object { '  ' + $_.Name + '  site=' + $_.SiteName + '  os=' + $_.OSVersion }
  ''
  'Trusts:'
  try {
    $trusts = $dom.GetAllTrustRelationships()
    if($trusts.Count -eq 0){ '  (none)' }
    else { $trusts | ForEach-Object { '  ' + $_.TargetName + '  direction=' + $_.TrustDirection + '  type=' + $_.TrustType } }
  } catch {
    '  ' + $_.Exception.Message
  }
} catch {
  W 'Domain info' $_.Exception.Message
}
"""
  ensureShell(c, true)
  let output = runCmd(c, cmd, false, true)
  if output.len > 0:
    stdout.write(output)
    if not output.endsWith("\n"):
      stdout.write("\n")
    stdout.flushFile()

proc opsecCheck(c: var WinRMClient) =
  let cmd = """
$ErrorActionPreference = 'Continue'
function Write-OpsecField($k,$v){ if($null -ne $v -and "$v".Length -gt 0){ "{0,-32} {1}" -f ($k + ':'), $v } }
function Get-OpsecRegValue($path,$name){
  try {
    $v = Get-ItemProperty -LiteralPath $path -Name $name -ErrorAction Stop
    return $v.$name
  } catch {
    return $null
  }
}
function Get-OpsecLogEnabled($log){
  try { return (Get-WinEvent -ListLog $log -ErrorAction Stop).IsEnabled } catch { return 'unavailable' }
}
function Get-OpsecRecentEventCount($log,$ids){
  try {
    $f = @{LogName=$log; StartTime=(Get-Date).AddHours(-24)}
    if($ids){ $f.Id = $ids }
    return @(Get-WinEvent -FilterHashtable $f -MaxEvents 20 -ErrorAction Stop).Count
  } catch {
    return 'unavailable'
  }
}

'== Identity / Session =='
Write-OpsecField 'User' ([Security.Principal.WindowsIdentity]::GetCurrent().Name)
Write-OpsecField 'Computer' $env:COMPUTERNAME
Write-OpsecField 'PowerShell version' $PSVersionTable.PSVersion
Write-OpsecField 'Host process' ((Get-Process -Id $PID).ProcessName + ' pid=' + $PID)
Write-OpsecField 'Current time' (Get-Date)
''

'== WinRM / PowerShell Logs =='
Write-OpsecField 'WinRM Operational enabled' (Get-OpsecLogEnabled 'Microsoft-Windows-WinRM/Operational')
Write-OpsecField 'PowerShell Operational enabled' (Get-OpsecLogEnabled 'Microsoft-Windows-PowerShell/Operational')
Write-OpsecField 'PowerShellCore Operational enabled' (Get-OpsecLogEnabled 'PowerShellCore/Operational')
Write-OpsecField 'Security log enabled' (Get-OpsecLogEnabled 'Security')
Write-OpsecField 'Recent WinRM events 24h' (Get-OpsecRecentEventCount 'Microsoft-Windows-WinRM/Operational' $null)
Write-OpsecField 'Recent PS 4103/4104 24h' (Get-OpsecRecentEventCount 'Microsoft-Windows-PowerShell/Operational' @(4103,4104))
Write-OpsecField 'Recent logon 4624 24h' (Get-OpsecRecentEventCount 'Security' @(4624))
''

'== PowerShell Logging Policy =='
$base = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell'
$sb = Join-Path $base 'ScriptBlockLogging'
$mod = Join-Path $base 'ModuleLogging'
$trans = Join-Path $base 'Transcription'
$v = Get-OpsecRegValue $sb 'EnableScriptBlockLogging'; Write-OpsecField 'ScriptBlockLogging' $v
$v = Get-OpsecRegValue $sb 'EnableScriptBlockInvocationLogging'; Write-OpsecField 'ScriptBlockInvocationLogging' $v
$v = Get-OpsecRegValue $mod 'EnableModuleLogging'; Write-OpsecField 'ModuleLogging' $v
try {
  $mods = (Get-ItemProperty -LiteralPath (Join-Path $mod 'ModuleNames') -ErrorAction Stop).PSObject.Properties |
    Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { $_.Name + '=' + $_.Value }
  Write-OpsecField 'Logged modules' ($mods -join ', ')
} catch { Write-OpsecField 'Logged modules' $null }
$v = Get-OpsecRegValue $trans 'EnableTranscripting'; Write-OpsecField 'Transcription' $v
$v = Get-OpsecRegValue $trans 'OutputDirectory'; Write-OpsecField 'Transcript directory' $v
$v = Get-OpsecRegValue $trans 'EnableInvocationHeader'; Write-OpsecField 'Invocation headers' $v
''

'== Process Creation / Command Line Auditing =='
$audit = & auditpol.exe /get /subcategory:'Process Creation' 2>$null
if($LASTEXITCODE -eq 0){ $audit | ForEach-Object { $_ } } else { Write-OpsecField 'auditpol' 'unavailable' }
$v = Get-OpsecRegValue 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled'; Write-OpsecField 'CommandLine in 4688' $v
''

'== Defender / AMSI Indicators =='
try {
  $mp = Get-MpComputerStatus -ErrorAction Stop
  Write-OpsecField 'Defender real-time' $mp.RealTimeProtectionEnabled
  Write-OpsecField 'Defender AM service' $mp.AMServiceEnabled
  Write-OpsecField 'Defender signatures' $mp.AntivirusSignatureLastUpdated
} catch { Write-OpsecField 'Defender status' $_.Exception.Message }
try {
  $pref = Get-MpPreference -ErrorAction Stop
  Write-OpsecField 'Defender exclusions path' (($pref.ExclusionPath | Select-Object -First 8) -join ', ')
  Write-OpsecField 'Defender exclusions proc' (($pref.ExclusionProcess | Select-Object -First 8) -join ', ')
} catch { Write-OpsecField 'Defender prefs' $_.Exception.Message }
''

'== Likely Event Trail =='
'WinRM logon/session activity: Microsoft-Windows-WinRM/Operational and Security 4624/4634/4672 where enabled.'
'PowerShell remoting activity: Microsoft-Windows-PowerShell/Operational, especially 4103/4104 when module/script block logging is enabled.'
'Process creation: Security 4688 when Audit Process Creation is enabled; command lines only if the registry policy above is enabled.'
'Transcript files: written when PowerShell Transcription is enabled and OutputDirectory is configured.'
"""
  ensureShell(c, true)
  let output = runCmd(c, cmd, false, true)
  if output.len > 0:
    stdout.write(output)
    if not output.endsWith("\n"):
      stdout.write("\n")
    stdout.flushFile()

proc runManagedAssemblyFromMemory(c: var WinRMClient, localPath: string, runArgs: seq[string]) =
  let data = readFile(localPath)
  if not isManagedPe(data):
    raise newException(ValueError, "local file is a native PE, not a managed .NET assembly; in-memory native PE execution requires a reflective PE loader")
  let b64 = encode(data)
  let varName = "wrm_payload_" & genUuid().replace("-", "")

  drawProgress("stage-mem", 0, b64.len)
  ensureShell(c)
  discard runCmd(c, "$script:" & varName & " = New-Object System.Text.StringBuilder", false)

  var off = 0
  try:
    while off < b64.len:
      let stop = min(off + InMemoryB64ChunkSize, b64.len)
      discard runCmd(c, "[void]$script:" & varName & ".Append(" & psQuote(b64[off ..< stop]) & ")", false)
      off = stop
      drawProgress("stage-mem", off, b64.len)
    echo ""

    let psArgs = psArray(runArgs)
    let cmd =
      "$ErrorActionPreference = 'Stop'; " &
      "$argv = " & psArgs & "; " &
      "$b64 = $script:" & varName & ".ToString(); " &
      "$script:" & varName & " = $null; " &
      "$bytes = [Convert]::FromBase64String($b64); " &
      "$b64 = $null; " &
      "try { $asm = [Reflection.Assembly]::Load($bytes) } catch [BadImageFormatException] { throw 'payload is a native PE, not a managed .NET assembly; in-memory native PE execution requires a reflective PE loader' }; " &
      "$bytes = $null; " &
      "$entry = $asm.EntryPoint; " &
      "if($null -eq $entry){throw 'managed assembly has no entry point'}; " &
      "$params = $entry.GetParameters(); " &
      "if($params.Count -eq 0){$invokeArgs = New-Object 'object[]' 0} " &
      "elseif($params.Count -eq 1 -and $params[0].ParameterType -eq [string[]]){$invokeArgs = New-Object 'object[]' 1; $invokeArgs[0] = [string[]]$argv} " &
      "else{throw ('unsupported entry point signature: ' + $entry.ToString())}; " &
      "$oldOut = [Console]::Out; $oldErr = [Console]::Error; " &
      "$out = New-Object IO.StringWriter; $err = New-Object IO.StringWriter; " &
      "try { " &
      "  [Console]::SetOut($out); [Console]::SetError($err); " &
      "  $ret = $entry.Invoke($null, $invokeArgs); " &
      "  if($ret -is [Threading.Tasks.Task]){$ret.GetAwaiter().GetResult()}; " &
      "} finally { " &
      "  [Console]::SetOut($oldOut); [Console]::SetError($oldErr); " &
      "}; " &
      "$stdout = $out.ToString(); $stderr = $err.ToString(); " &
      "if($stdout.Length -gt 0){$stdout}; if($stderr.Length -gt 0){$stderr}"

    let output = runCmd(c, cmd, false)
    if output.len > 0:
      stdout.write(output)
      if not output.endsWith("\n"):
        stdout.write("\n")
      stdout.flushFile()
  finally:
    try:
      discard runCmd(c, "$script:" & varName & " = $null; [GC]::Collect()", false)
    except:
      discard

proc runManagedAssemblyFromRemotePath(c: var WinRMClient, remotePath: string, runArgs: seq[string]) =
  let setup = cwdPrefix(c) & remotePathSetup("p", remotePath, "")
  let psArgs = psArray(runArgs)
  let cmd =
    "$ErrorActionPreference = 'Stop'; " &
    setup &
    "if(-not (Test-Path -LiteralPath $p -PathType Leaf)){throw ('remote file not found: ' + $p)}; " &
    "$argv = " & psArgs & "; " &
    "$bytes = [IO.File]::ReadAllBytes($p); " &
    "try { $asm = [Reflection.Assembly]::Load($bytes) } catch [BadImageFormatException] { throw 'payload is a native PE, not a managed .NET assembly; in-memory native PE execution requires a reflective PE loader' }; " &
    "$bytes = $null; " &
    "$entry = $asm.EntryPoint; " &
    "if($null -eq $entry){throw 'managed assembly has no entry point'}; " &
    "$params = $entry.GetParameters(); " &
    "if($params.Count -eq 0){$invokeArgs = New-Object 'object[]' 0} " &
    "elseif($params.Count -eq 1 -and $params[0].ParameterType -eq [string[]]){$invokeArgs = New-Object 'object[]' 1; $invokeArgs[0] = [string[]]$argv} " &
    "else{throw ('unsupported entry point signature: ' + $entry.ToString())}; " &
    "$oldOut = [Console]::Out; $oldErr = [Console]::Error; " &
    "$out = New-Object IO.StringWriter; $err = New-Object IO.StringWriter; " &
    "try { " &
    "  [Console]::SetOut($out); [Console]::SetError($err); " &
    "  $ret = $entry.Invoke($null, $invokeArgs); " &
    "  if($ret -is [Threading.Tasks.Task]){$ret.GetAwaiter().GetResult()}; " &
    "} finally { " &
    "  [Console]::SetOut($oldOut); [Console]::SetError($oldErr); " &
    "}; " &
    "$stdout = $out.ToString(); $stderr = $err.ToString(); " &
    "if($stdout.Length -gt 0){$stdout}; if($stderr.Length -gt 0){$stderr}"

  let output = runCmdFast(c, cmd, false)
  if output.len > 0:
    stdout.write(output)
    if not output.endsWith("\n"):
      stdout.write("\n")
    stdout.flushFile()

proc executeAssembly(c: var WinRMClient, args: seq[string]) =
  if args.len < 1:
    raise newException(ValueError, "usage: execute-assembly <local-or-remote-assembly> [args...]")

  let src = args[0]
  let localPath = if isAbsolute(src): src else: getCurrentDir() / src
  let runArgs = if args.len > 1: args[1..^1] else: @[]

  if fileExists(localPath):
    runManagedAssemblyFromMemory(c, localPath, runArgs)
    return

  runManagedAssemblyFromRemotePath(c, remoteExecPath(src), runArgs)

proc downloadFile(c: var WinRMClient, args: seq[string]) =
  if args.len < 1 or args.len > 2:
    raise newException(ValueError, "usage: download <remote-file> [local-file-or-dir]")
  let remoteArg = args[0]
  let localPath = localDownloadPath(remoteArg, if args.len == 2: args[1] else: "")
  let setup = cwdPrefix(c) & remotePathSetup("p", remoteArg, "")
  let resolved = resolveRemoteFile(c, setup, remoteArg)
  let total = resolved.size
  if total == 0:
    writeFile(localPath, "")
    styledEcho(fgGreen, "[+] Downloaded 0 bytes to " & localPath)
    return

  var data = newStringOfCap(total)
  if not c.cmdShellDenied:
    try:
      statusLine(fgWhite, "[*] Download mode: WinRS binary stream")
      drawProgress("download", 0, total)
      let binCmd = setup &
        "$ErrorActionPreference='Stop'; " &
        "if(-not (Test-Path -LiteralPath $p -PathType Leaf)){throw ('remote file not found: ' + $p)}; " &
        "$buf = New-Object byte[] " & $DownloadBinaryChunkSize & "; " &
        "$fs = [IO.File]::Open($p, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite); " &
        "$out = [Console]::OpenStandardOutput(); " &
        "try { while(($n = $fs.Read($buf, 0, $buf.Length)) -gt 0) { $out.Write($buf, 0, $n); $out.Flush() } } finally {$fs.Close(); $out.Close()}"
      proc collectBinary(chunk: string) =
        data.add chunk
        drawProgress("download", min(data.len, total), total)
      discard runBinaryFastCached(c, binCmd, collectBinary)
      if data.len < total:
        raise newException(IOError, "WinRS binary download returned partial data: expected " & $total & " bytes, got " & $data.len)
      if data.len > total:
        data.setLen(total)
      drawProgress("download", data.len, total)
      echo ""
      writeFile(localPath, data)
      styledEcho(fgGreen, "[+] Downloaded " & $data.len & " bytes to " & localPath)
      return
    except Exception as e:
      let msg = e.msg.toLowerAscii()
      if "access is denied" in msg or "could not find shellid" in msg or
         "winrm error 500" in msg or "not supported" in msg or
         "wsman" in msg:
        c.cmdShellDenied = true
        data.setLen(0)
      else:
        raise

  var pendingB64 = ""
  if c.cmdShellDenied:
    statusLine(fgWhite, "[*] Download mode: PSRP base64 stream")
  else:
    statusLine(fgWhite, "[*] Download mode: WinRS base64 stream")
  drawProgress("download", 0, total)

  let readChunkSize = if c.cmdShellDenied: PsrpDownloadChunkSize else: DownloadChunkSize
  let lineChars = if c.cmdShellDenied: PsrpDownloadLineChars else: DownloadLineChars
  let cmd = setup &
    "if(-not (Test-Path -LiteralPath $p -PathType Leaf)){throw ('remote file not found: ' + $p)}; " &
    "$buf = New-Object byte[] " & $readChunkSize & "; " &
    "$fs = [IO.File]::Open($p, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite); " &
    "try { while(($n = $fs.Read($buf, 0, $buf.Length)) -gt 0) { " &
    "if($n -lt $buf.Length){$tmp = New-Object byte[] $n; [Array]::Copy($buf, $tmp, $n); $part = $tmp} else {$part = $buf}; " &
    "$s = [Convert]::ToBase64String($part); " &
    "for($i = 0; $i -lt $s.Length; $i += " & $lineChars & "){$s.Substring($i, [Math]::Min(" & $lineChars & ", $s.Length - $i))} " &
    "} } finally {$fs.Close()}"

  proc collectDownload(chunkText: string) =
    for ch in chunkText:
      if ch in {'\r', '\n'}:
        let part = pendingB64.strip()
        if part != "":
          data.add decode(part)
          pendingB64.setLen(0)
      elif not (ch in {' ', '\t'}):
        pendingB64.add ch
    drawProgress("download", min(data.len, total), total)

  discard runCmdFastCached(c, cmd, false, collectDownload)
  let finalPart = pendingB64.strip()
  if finalPart != "":
    data.add decode(finalPart)
  if data.len == 0:
    raise newException(IOError, "download returned no data from " & (if c.cmdShellDenied: "PSRP" else: "WinRS") & " base64 stream")
  if data.len != total:
    raise newException(IOError, "remote download size mismatch: expected " & $total & " bytes, got " & $data.len)
  drawProgress("download", data.len, total)

  echo ""
  writeFile(localPath, data)
  styledEcho(fgGreen, "[+] Downloaded " & $data.len & " bytes to " & localPath)

proc localDownloadDirPath(remoteArg, localArg: string): string =
  let name = remoteBaseName(remoteArg)
  if localArg == "":
    return getCurrentDir() / name
  if dirExists(localArg):
    return localArg / name
  result = localArg

proc downloadDir(c: var WinRMClient, args: seq[string]) =
  if args.len < 1 or args.len > 2:
    raise newException(ValueError, "usage: download-dir <remote-dir> [local-dir]")

  let remoteArg = args[0]
  let localRoot = absolutePath(localDownloadDirPath(remoteArg, if args.len == 2: args[1] else: ""))
  let setup = cwdPrefix(c) & remotePathSetup("p", remoteArg, "")
  let resolvedRoot = resolveRemoteDir(c, setup, remoteArg)
  let listCmd = setup &
    "$root = " & psQuote(resolvedRoot) & "; " &
    "$enc = [Text.Encoding]::UTF8; " &
    "'R ' + [Convert]::ToBase64String($enc.GetBytes($root)); " &
    "Get-ChildItem -LiteralPath $root -Force -Recurse -Directory | ForEach-Object { " &
    "$rel = $_.FullName.Substring($root.Length).TrimStart([char[]]'\\/'); " &
    "'D ' + [Convert]::ToBase64String($enc.GetBytes($rel)) }; " &
    "Get-ChildItem -LiteralPath $root -Force -Recurse -File | ForEach-Object { " &
    "$rel = $_.FullName.Substring($root.Length).TrimStart([char[]]'\\/'); " &
    "'F ' + [Convert]::ToBase64String($enc.GetBytes($rel)) }"

  var remoteRoot: string
  var dirs, files: seq[string]
  for rawLine in runCmdFastCached(c, listCmd, false).splitLines():
    let line = rawLine.strip()
    if line.len < 3: continue
    let kind = line[0]
    if line[1] != ' ': continue
    var decoded: string
    try:
      decoded = decode(line[2..^1])
    except:
      continue
    case kind
    of 'R': remoteRoot = decoded
    of 'D': dirs.add decoded
    of 'F': files.add decoded
    else: discard

  if remoteRoot == "":
    raise newException(IOError, "could not resolve remote directory: " & remoteArg)

  createDir(localRoot)
  for d in dirs:
    createDir(localJoinRel(localRoot, d))

  var done = 0
  for f in files:
    inc done
    let localPath = localJoinRel(localRoot, f)
    let parent = parentDir(localPath)
    if parent != "":
      createDir(parent)
    styledEcho(fgYellow, fmt"[*] download-dir [{done}/{files.len}] {f}")
    downloadFile(c, @[remoteJoin(remoteRoot, f), localPath])

  styledEcho(fgGreen, fmt"[+] Downloaded directory {remoteRoot} to {localRoot} ({files.len} files, {dirs.len} dirs)")

proc banner() =
  styledEcho(fgCyan,
    "        _                 \n" &
    "  _ __ (_)_ __ ___  _ __ _ __ ___\n" &
    " | '_ \\| | '_ ` _ \\| '__| '_ ` _ \\\n" &
    " | | | | | | | | | | |  | | | | | |\n" &
    " |_| |_|_|_| |_| |_|_|  |_| |_| |_|\n" &
    "       native WinRM operator shell\n")
  styledEcho(fgYellow, "  nimrm | NTLM & Kerberos | PS / CMD | file transfer | in-memory helpers")
  styledEcho(fgRed, "  Legal: use only on systems you own or are authorized to administer.")
  echo ""

proc usage() =
  echo """
Usage:
  nimrm -T <host> -A <user[@domain]> -P <password> [options]
  nimrm -T <host> -A <user[@domain]> -N <nthash|lm:nthash> [options]
  nimrm -T <host> -A <user@REALM> -k [options]

Options:
  -T, --target     Target IP or hostname
  -A, --account    Username  (user, user@domain, or DOMAIN\\user)
  -P, --secret     Password  (NTLM auth)
  -p, --port       WinRM port  (default 5985, or 5986 with --tls)
  -N, --nt-proof   NT hash or LM:NT hash  (NTLM pass-the-hash)
  -Z, --krb-zone   Kerberos realm  (overrides domain from -A)
  -K, --kerb-spn   Kerberos SPN override  (e.g. HTTP/dc01.corp.local@CORP.LOCAL)
  -k, --kerb       Use Kerberos auth (reads KRB5CCNAME env var)
  -c, --command    Execute one remote command, print output, then exit
      --tls        Use HTTPS on port 5986
  -h, --help       This help

 Shell commands:
  /help              Show this help
  exit / quit        Close shell and exit
  !<cmd>             Run as CMD  (e.g. !dir C:\\)
  upload <l> [r]     Upload local file to remote pwd or custom remote path
  download <r> [l]   Download remote file to local pwd or custom local path
  upload-dir <l> [r] Recursively upload local directory
  download-dir <r> [l] Recursively download remote directory
  invoke-script <f> [a] Run local PowerShell script from memory
  ad-info            Show AD/domain context using LDAP/.NET
  opsec-check        Show logging, auditing, and PowerShell policy posture
  execute-assembly <f> [a] Run .NET exe/dll from local bytes or remote file bytes in memory
  anything else      Run as PowerShell  (EncodedCommand)

 Session management:
  sessions           List all active sessions
  session <opts>     Create new session  (e.g. session -T host -A user -P pass [-n name])
  use <name|id>      Switch to a session
  kill <name|id>     Close and remove a session
"""

when defined(posix):
  import posix

  type Termios {.importc: "struct termios", header: "<termios.h>".} = object
    c_iflag, c_oflag, c_cflag, c_lflag: cuint
    c_cc: array[32, char]

  proc tcgetattr(fd: cint; t: ptr Termios): cint {.importc, header: "<termios.h>".}
  proc tcsetattr(fd: cint; action: cint; t: ptr Termios): cint {.importc, header: "<termios.h>".}

  const TCSANOW_C = 0.cint
  const F_ICANON  = 0x00000002.cuint
  const F_ECHO    = 0x00000008.cuint
  const VMIN_I    = 6
  const VTIME_I   = 5

  proc rawRead(): char =
    var ch: char
    discard posix.read(STDIN_FILENO, addr ch, 1)
    ch

proc readLineHistory*(prompt: string; history: var seq[string]): string =
  when not defined(posix):
    stdout.write(prompt); stdout.flushFile()
    return stdin.readLine()
  else:
    var orig: Termios
    discard tcgetattr(STDIN_FILENO, addr orig)
    var raw = orig
    raw.c_lflag = raw.c_lflag and not (F_ICANON or F_ECHO)
    raw.c_cc[VMIN_I]  = '\x01'
    raw.c_cc[VTIME_I] = '\x00'
    discard tcsetattr(STDIN_FILENO, TCSANOW_C, addr raw)

    stdout.write(prompt); stdout.flushFile()

    var buf     = ""
    var cursor  = 0
    var histIdx = history.len
    var saved   = ""

    proc redraw() =
      stdout.write("\r\x1b[2K" & prompt & buf)
      let back = buf.len - cursor
      if back > 0:
        stdout.write("\x1b[" & $back & "D")
      stdout.flushFile()

    while true:
      let c = rawRead()
      case c
      of '\r', '\n':
        stdout.write("\n"); stdout.flushFile()
        result = buf; break
      of '\x7f', '\x08':
        if cursor > 0:
          buf.delete((cursor - 1)..(cursor - 1))
          dec cursor
          redraw()
      of '\x1b':
        let c2 = rawRead()
        if c2 == '[':
          let c3 = rawRead()
          case c3
          of 'A':
            if histIdx == history.len: saved = buf
            if histIdx > 0:
              dec histIdx
              buf = history[histIdx]
              cursor = buf.len
              redraw()
          of 'B':
            if histIdx < history.len:
              inc histIdx
              buf = if histIdx == history.len: saved else: history[histIdx]
              cursor = buf.len
              redraw()
          of 'C':
            if cursor < buf.len:
              inc cursor
              stdout.write("\x1b[C"); stdout.flushFile()
          of 'D':
            if cursor > 0:
              dec cursor
              stdout.write("\x1b[D"); stdout.flushFile()
          else: discard
        else: discard
      of '\x03':
        stdout.write("\n"); stdout.flushFile()
        result = ""; break
      else:
        buf.insert($c, cursor)
        inc cursor
        redraw()

    discard tcsetattr(STDIN_FILENO, TCSANOW_C, addr orig)

var sessions: seq[Session] = @[]
var activeIdx = -1

proc activeSession(): Session =
  if activeIdx >= 0 and activeIdx < sessions.len: sessions[activeIdx] else: nil

proc findSession(name: string): int =
  for i, s in sessions:
    if s.name == name: return i
  try:
    let idx = parseInt(name) - 1
    if idx >= 0 and idx < sessions.len: return idx
  except:
    discard
  return -1

proc listSessions() =
  if sessions.len == 0:
    styledEcho(fgYellow, "[*] No active sessions")
    return
  echo ""
  styledEcho(fgWhite, "  ID  Name              Target                    User              Auth")
  styledEcho(fgWhite, "  --  ----              ------                    ----              ----")
  for i, s in sessions:
    let marker = if i == activeIdx: " *" else: "  "
    let id = align($(i + 1), 2)
    let name = alignLeft(s.name, 16)
    let target = alignLeft(s.host, 24)
    let user = alignLeft(if s.user != "": s.user else: "(kerberos)", 16)
    let color = if i == activeIdx: fgGreen else: fgWhite
    styledEcho(color, marker & id & "  " & name & "  " & target & "  " & user & "  " & s.authStr)
  echo ""

proc killSession(name: string) =
  let idx = findSession(name)
  if idx < 0:
    styledEcho(fgRed, "[!] Session not found: " & name)
    return
  let s = sessions[idx]
  try:
    deleteShell(s.client)
    closeNtlm(s.client)
  except:
    discard
  styledEcho(fgYellow, "[*] Killed session: " & s.name)
  sessions.delete(idx)
  if activeIdx == idx:
    activeIdx = if sessions.len > 0: 0 else: -1
  elif activeIdx > idx:
    dec activeIdx

proc switchSession(name: string) =
  let idx = findSession(name)
  if idx < 0:
    styledEcho(fgRed, "[!] Session not found: " & name)
    return
  activeIdx = idx
  let s = sessions[idx]
  styledEcho(fgGreen, "[*] Switched to session: " & s.name & " (" & s.host & ")")

proc createNewSession(args: seq[string]) =
  var host, username, password, ntHash, realm, spn: string
  var customPort = 0
  var portSet = false
  var useKerb = false
  var useSSL = false
  var sessionName = ""

  var i = 0
  while i < args.len:
    let a = args[i]
    case a
    of "-T", "--target":
      if i + 1 < args.len: inc i; host = args[i]
    of "-A", "--account":
      if i + 1 < args.len: inc i; username = args[i]
    of "-P", "--secret":
      if i + 1 < args.len: inc i; password = args[i]
    of "-N", "--nt-proof":
      if i + 1 < args.len: inc i; ntHash = args[i]
    of "-Z", "--krb-zone":
      if i + 1 < args.len: inc i; realm = args[i]
    of "-K", "--kerb-spn":
      if i + 1 < args.len: inc i; spn = args[i]
    of "-k", "--kerb":
      useKerb = true
    of "--tls", "--ssl":
      useSSL = true
    of "-p", "--port":
      if i + 1 < args.len:
        inc i
        try: customPort = parseInt(args[i]); portSet = true
        except: styledEcho(fgRed, "[!] Invalid port"); return
    of "-n", "--name":
      if i + 1 < args.len: inc i; sessionName = args[i]
    else:
      discard
    inc i

  if host == "":
    styledEcho(fgRed, "[!] -T <host> is required")
    return
  if username == "" and not useKerb:
    styledEcho(fgRed, "[!] -A <user> is required (or use -k for Kerberos)")
    return
  if password == "" and ntHash == "" and not useKerb:
    styledEcho(fgRed, "[!] -P <password> or -N <hash> or -k is required")
    return

  var user = username
  var domain = realm
  if "@" in username:
    let parts = username.split('@')
    user = parts[0]
    if domain == "": domain = parts[1]
  elif "\\" in username:
    let parts = username.split('\\')
    if domain == "": domain = parts[0]
    user = parts[1]

  if useKerb:
    var cc = getEnv("KRB5CCNAME")
    const schemes = ["FILE:", "MEMORY:", "DIR:", "API:", "KCM:", "KEYRING:"]
    var hasScheme = false
    for s in schemes:
      if cc.startsWith(s): hasScheme = true; break
    if cc != "" and not hasScheme:
      cc = "FILE:" & absolutePath(cc)
    if cc != "":
      putEnv("KRB5CCNAME", cc)

  let port = if portSet: customPort else: (if useSSL: 5986 else: 5985)
  let authStr = if useKerb: "Kerberos" else: "NTLM"
  let authMethod = if useKerb: amKerberos else: amNtlm

  if sessionName == "":
    var n = sessions.len + 1
    while true:
      sessionName = "session-" & $n
      var exists = false
      for s in sessions:
        if s.name == sessionName: exists = true; break
      if not exists: break
      inc n

  for s in sessions:
    if s.name == sessionName:
      styledEcho(fgRed, "[!] Session name already exists: " & sessionName)
      return

  styledEcho(fgWhite, "[*] Connecting to " & host & ":" & $port & " ...")
  var client = newClient(host, user, password, ntHash, spn, domain, authMethod, useSSL, port)

  try:
    warmSmartShell(client)
  except Exception as e:
    styledEcho(fgRed, "[!] Connection failed: " & e.msg)
    try: closeNtlm(client)
    except: discard
    return

  var currentPath = if user != "": "C:\\Users\\" & user else: ""
  if currentPath == "":
    try:
      currentPath = runCmdFastOrPsrp(client, "(Get-Location).Path", false).strip()
    except:
      discard
  client.remoteCwd = currentPath

  let s = Session(
    name: sessionName,
    client: client,
    currentPath: currentPath,
    host: host & ":" & $port,
    user: user,
    authStr: authStr,
    connected: true)
  sessions.add(s)
  activeIdx = sessions.len - 1
  styledEcho(fgGreen, "[+] Session created: " & sessionName & " (" & host & ":" & $port & ")")

proc main() =
  randomize()

  var host, username, password, ntHash, realm, spn, execCommand: string
  var customPort = 0
  var portSet = false
  var useKerb = false
  var useSSL  = false

  var argv = commandLineParams()
  for i in 0..<argv.len:
    if argv[i] == "-spn":
      argv[i] = "--spn"
    elif argv[i] == "-kspn":
      argv[i] = "--kerb-spn"
  var p = initOptParser(argv)

  proc nextVal(p: var OptParser): string =
    if p.val != "": return p.val
    p.next()
    if p.kind == cmdArgument: return p.key
    return ""

  while true:
    p.next()
    case p.kind
    of cmdEnd: break
    of cmdShortOption, cmdLongOption:
      let optKey = p.key
      if optKey == "K":
        spn = nextVal(p)
        continue
      if optKey == "P":
        password = nextVal(p)
        continue
      if optKey == "p":
        try:
          customPort = parseInt(nextVal(p))
          portSet = true
        except:
          styledEcho(fgRed, "[!] -p/--port must be a number")
          quit(1)
        continue
      case optKey.toLowerAscii()
      of "t", "target", "i", "ip":
        host = nextVal(p)
      of "a", "account", "u", "user":
        username = nextVal(p)
      of "secret", "pass":
        password = nextVal(p)
      of "port":
        try:
          customPort = parseInt(nextVal(p))
          portSet = true
        except:
          styledEcho(fgRed, "[!] -p/--port must be a number")
          quit(1)
      of "n", "nt-proof", "hash":
        ntHash = nextVal(p)
      of "z", "krb-zone", "r", "realm":
        realm = nextVal(p)
      of "c", "command", "cmd", "exec":
        execCommand = nextVal(p)
      of "kerb-spn", "spn": spn = nextVal(p)
      of "k", "kerb":  useKerb  = true
      of "tls", "ssl": useSSL   = true
      of "h":
        if optKey == "H":
          ntHash = nextVal(p)
        else:
          banner(); usage(); quit(0)
      of "help":       banner(); usage(); quit(0)
      else: discard
    of cmdArgument: discard

  banner()

  if host == "":
    styledEcho(fgRed, "[!] -T <host> is required"); usage(); quit(1)
  if username == "" and not useKerb:
    styledEcho(fgRed, "[!] -A <user> is required"); quit(1)
  if password == "" and ntHash == "" and not useKerb:
    stdout.write("Password: ")
    stdout.flushFile()
    when defined(posix):
      var cmd = "stty -echo"
      discard execShellCmd(cmd)
    password = stdin.readLine()
    when defined(posix):
      discard execShellCmd("stty echo")
    echo ""

  var user   = username
  var domain = realm
  if "@" in username:
    let parts = username.split('@')
    user = parts[0]
    if domain == "": domain = parts[1]
  elif "\\" in username:
    let parts = username.split('\\')
    if domain == "": domain = parts[0]
    user = parts[1]

  if useKerb:
    var cc = getEnv("KRB5CCNAME")
    const schemes = ["FILE:", "MEMORY:", "DIR:", "API:", "KCM:", "KEYRING:"]
    var hasScheme = false
    for s in schemes:
      if cc.startsWith(s): hasScheme = true; break
    if cc != "" and not hasScheme:
      cc = "FILE:" & absolutePath(cc)
    if cc != "":
      putEnv("KRB5CCNAME", cc)
      styledEcho(fgGreen, "[*] KRB5CCNAME = " & cc)
    else:
      styledEcho(fgYellow, "[~] KRB5CCNAME not set, using default ccache")

  if portSet and (customPort < 1 or customPort > 65535):
    styledEcho(fgRed, "[!] -p/--port must be between 1 and 65535")
    quit(1)

  let port = if portSet: customPort else: (if useSSL: 5986 else: 5985)
  let authStr = if useKerb: "Kerberos" else: "NTLM"

  styledEcho(fgGreen, fmt"[*] Target  : {host}:{port}")
  if username != "":
    styledEcho(fgGreen, fmt"[*] User    : {username}")
  if domain != "":
    styledEcho(fgGreen, fmt"[*] Domain  : {domain}")
  if spn != "":
    styledEcho(fgGreen, fmt"[*] SPN     : {spn}")
  styledEcho(fgGreen, fmt"[*] Auth    : {authStr}")
  styledEcho(fgGreen, fmt"[*] SSL     : {useSSL}")
  echo ""

  let authMethod = if useKerb: amKerberos else: amNtlm
  var client = newClient(host, user, password, ntHash, spn, domain, authMethod, useSSL, port)
  if getEnv("WINRMSHELL_DEBUG") == "1":
    styledEcho(fgYellow, "[debug] client initialized")

  if execCommand != "":
    try:
      if getEnv("WINRMSHELL_DEBUG") == "1":
        styledEcho(fgYellow, "[debug] executing -c command")
      warmSmartShell(client)
      let isCmd = execCommand.startsWith("!")
      let cmd = if isCmd: execCommand[1..^1].strip() else: execCommand
      var streamed = false
      proc writeChunk(chunk: string) =
        streamed = true
        stdout.write(chunk)
        stdout.flushFile()
      let output = runCmdFastCached(client, cmd, isCmd, writeChunk)
      if output.len > 0 and not streamed:
        stdout.write(output)
        if not output.endsWith("\n"):
          stdout.write("\n")
        stdout.flushFile()
      elif streamed and not output.endsWith("\n"):
        stdout.write("\n")
        stdout.flushFile()
    except Exception as e:
      styledEcho(fgRed, "[!] Error: " & e.msg)
      quit(1)
    deleteShell(client)
    closeNtlm(client)
    quit(0)

  echo ""
  styledEcho(fgWhite, "Connecting...")
  try:
    warmSmartShell(client)
    styledEcho(fgGreen, "[*] Shell   : ready")
  except Exception as e:
    if isAuthFailure(e):
      styledEcho(fgRed, "[!] Authentication failed: " & e.msg)
    else:
      styledEcho(fgRed, "[!] Shell pre-open failed: " & e.msg)
    closeNtlm(client)
    quit(1)
  styledEcho(fgWhite, "Type commands below. 'exit'/'quit' to end. Prefix '!' for CMD.")
  echo ""

  var currentPath = if user != "": "C:\\Users\\" & user else: ""
  if currentPath == "":
    try:
      currentPath = runCmdFastOrPsrp(client, "(Get-Location).Path", false).strip()
    except:
      discard
  client.remoteCwd = currentPath

  let initSession = Session(
    name: "session-1",
    client: client,
    currentPath: currentPath,
    host: host & ":" & $port,
    user: user,
    authStr: authStr,
    connected: true)
  sessions.add(initSession)
  activeIdx = 0

  var cmdHistory: seq[string] = @[]
  while true:
    let cur = activeSession()
    if cur == nil:
      styledEcho(fgYellow, "[*] No active session. Use 'session -T <host> ...' to create one or 'exit' to quit.")
      let promptStr = ansiForegroundColorCode(fgRed) & "nimrm> " & ansiResetCode
      var line: string
      try:
        line = readLineHistory(promptStr, cmdHistory).strip()
      except EOFError:
        echo ""; break
      if line == "": continue
      if line.toLowerAscii() in ["exit", "quit"]: break
      cmdHistory.add(line)
      let words = shellSplit(line)
      let verb = if words.len > 0: words[0].toLowerAscii() else: ""
      if verb == "session" and words.len > 1:
        createNewSession(words[1..^1])
      elif verb == "sessions":
        listSessions()
      elif verb in ["/help", "help"]:
        usage()
      else:
        styledEcho(fgRed, "[!] No active session")
      continue

    let sessionTag = if sessions.len > 1: "[" & cur.name & "] " else: ""
    let promptStr = ansiForegroundColorCode(fgCyan) &
      sessionTag &
      (if cur.currentPath != "": "PS " & cur.currentPath & "> " else: "PS> ") &
      ansiResetCode

    var line: string
    try:
      line = readLineHistory(promptStr, cmdHistory).strip()
    except EOFError:
      echo ""; break

    if line == "": continue
    if line.toLowerAscii() in ["exit", "quit"]: break
    cmdHistory.add(line)

    try:
      let words = shellSplit(line)
      let verb = if words.len > 0: words[0].toLowerAscii() else: ""
      if verb in ["/help", "help"]:
        usage()
      elif verb == "sessions":
        listSessions()
      elif verb == "session":
        if words.len > 1:
          createNewSession(words[1..^1])
        else:
          styledEcho(fgWhite, "Usage: session -T <host> -A <user> -P <pass> [-n name] [-k] [--tls]")
      elif verb == "use" and words.len >= 2:
        switchSession(words[1])
      elif verb == "kill" and words.len >= 2:
        killSession(words[1])
      elif verb == "upload":
        uploadFile(cur.client, words[1..^1])
      elif verb == "download":
        downloadFile(cur.client, words[1..^1])
      elif verb == "upload-dir":
        uploadDir(cur.client, words[1..^1])
      elif verb == "download-dir":
        downloadDir(cur.client, words[1..^1])
      elif verb == "invoke-script":
        invokeScript(cur.client, words[1..^1])
      elif verb == "ad-info":
        adInfo(cur.client)
      elif verb == "opsec-check":
        opsecCheck(cur.client)
      elif verb in ["execute-assembly", "exec-assembly"]:
        executeAssembly(cur.client, words[1..^1])
      else:
        let isCmd = line.startsWith("!")
        let cmd = if isCmd: line[1..^1].strip() else: line
        let isDirChange = verb in ["cd", "set-location", "sl", "chdir",
                                   "pushd", "push-location", "popd", "pop-location"]
        var output: string
        if isDirChange and not isCmd:
          let prefix = if cur.currentPath != "": "Set-Location " & psQuote(cur.currentPath) & "; "
                       else: "Set-Location $env:USERPROFILE; "
          let target = if words.len >= 2: words[1] else: ""
          let fallback = if target != "" and not target.contains(":") and not target.startsWith("\\") and not target.startsWith("/") and target notin [".", ".."]:
            "try{Set-Location (Join-Path $env:USERPROFILE " & psQuote(target) & ")}catch{Write-Error $__nimrm_cd_err.Exception.Message};"
          else:
            "Write-Error $__nimrm_cd_err.Exception.Message;"
          let raw = runCmdFastCached(cur.client,
            prefix & "$ErrorActionPreference='Stop';try{" & cmd & "}catch{$__nimrm_cd_err = $_;" & fallback & "};" &
            "Write-Output \"##CD##$((Get-Location).Path)\"", false)
          var outLines: seq[string]
          for ln in raw.splitLines():
            if ln.startsWith("##CD##"):
              cur.currentPath = ln[6..^1].strip()
              cur.client.remoteCwd = cur.currentPath
            else:
              outLines.add(ln)
          while outLines.len > 0 and outLines[^1].strip() == "":
            outLines.setLen(outLines.len - 1)
          output = if outLines.len > 0: outLines.join("\n") & "\n" else: ""
        elif not isCmd and cur.currentPath != "":
          output = runCmdFastCached(cur.client, "Set-Location " & psQuote(cur.currentPath) & "; " & cmd, false)
        else:
          output = runCmdFastCached(cur.client, cmd, isCmd)
        if output.len > 0:
          stdout.write(output)
          if not output.endsWith("\n"):
            stdout.write("\n")
          stdout.flushFile()
    except Exception as e:
      styledEcho(fgRed, "\n[!] Error: " & e.msg)
      if isAuthFailure(e) or isConnectionLostMessage(e.msg):
        styledEcho(fgYellow, "[*] Session lost: " & cur.name)
        cur.connected = false
        if sessions.len > 1:
          killSession(cur.name)
          continue
        else:
          break

  for s in sessions:
    try:
      styledEcho(fgYellow, "[*] Closing session: " & s.name)
      deleteShell(s.client)
      closeNtlm(s.client)
    except:
      discard
  styledEcho(fgGreen, "[+] Done. Goodbye!")

main()
