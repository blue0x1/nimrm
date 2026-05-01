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
  httpclient, parseopt, terminal, times, random
]

const
  WSManMaxEnvelope = 640000
  UploadChunkSize = 262144
  DownloadChunkSize = 196608
  InMemoryB64ChunkSize = 196608


when defined(linux):
  const gssLib = "libgssapi_krb5.so.2"
elif defined(macosx):
  const gssLib = "libgssapi_krb5.dylib"
else:
  const gssLib = "libgssapi_krb5.so.2"

{.emit: "/*INCLUDESECTION*/\ntypedef void* gss_ctx_id_t;\ntypedef void* gss_cred_id_t;\ntypedef void* gss_name_t;".}

type
  GssUint32  = uint32
  GssOidDesc = object
    length*:   GssUint32
    elements*: pointer
  GssOid = ptr GssOidDesc

  GssBufferDesc = object
    length*: csize_t
    value*:  pointer
  GssBuffer = ptr GssBufferDesc

  GssIovBufferDesc = object
    typ*:    GssUint32
    buffer*: GssBufferDesc

  GssCtxId  {.importc: "gss_ctx_id_t",  nodecl.} = pointer
  GssCredId {.importc: "gss_cred_id_t", nodecl.} = pointer
  GssNameT  {.importc: "gss_name_t",    nodecl.} = pointer

const
  GSS_S_COMPLETE        = 0'u32
  GSS_S_CONTINUE_NEEDED = 1'u32

var
  GSS_C_NO_CREDENTIAL* : GssCredId = nil
  GSS_C_NO_OID*        : GssOid    = nil

proc gss_import_name(
  minor:    ptr GssUint32,
  input:    GssBuffer,
  nameType: GssOid,
  output:   ptr GssNameT
): GssUint32 {.importc, dynlib: gssLib.}

proc gss_init_sec_context(
  minor:        ptr GssUint32,
  cred:         GssCredId,
  ctx:          ptr GssCtxId,
  target:       GssNameT,
  mechType:     GssOid,
  reqFlags:     GssUint32,
  timeReq:      GssUint32,
  chanBindings: pointer,
  input:        GssBuffer,
  actualMech:   ptr GssOid,
  output:       GssBuffer,
  retFlags:     ptr GssUint32,
  timeRec:      ptr GssUint32
): GssUint32 {.importc, dynlib: gssLib.}

proc gss_release_buffer(
  minor: ptr GssUint32,
  buf:   GssBuffer
): GssUint32 {.importc, dynlib: gssLib.}

proc gss_release_name(
  minor: ptr GssUint32,
  name:  ptr GssNameT
): GssUint32 {.importc, dynlib: gssLib.}

proc gss_delete_sec_context(
  minor: ptr GssUint32,
  ctx:   ptr GssCtxId,
  buf:   GssBuffer
): GssUint32 {.importc, dynlib: gssLib.}

proc gss_display_status(
  minor:      ptr GssUint32,
  status:     GssUint32,
  statusType: cint,
  mechType:   GssOid,
  msgCtx:     ptr GssUint32,
  output:     GssBuffer
): GssUint32 {.importc, dynlib: gssLib.}

proc gss_wrap(
  minor:     ptr GssUint32,
  ctx:       GssCtxId,
  confReq:   cint,
  qopReq:    GssUint32,
  input:     GssBuffer,
  confState: ptr cint,
  output:    GssBuffer
): GssUint32 {.importc, dynlib: gssLib.}

proc gss_unwrap(
  minor:     ptr GssUint32,
  ctx:       GssCtxId,
  input:     GssBuffer,
  output:    GssBuffer,
  confState: ptr cint,
  qopState:  ptr GssUint32
): GssUint32 {.importc, dynlib: gssLib.}

proc gss_wrap_iov(
  minor:     ptr GssUint32,
  ctx:       GssCtxId,
  confReq:   cint,
  qopReq:    GssUint32,
  confState: ptr cint,
  iov:       ptr GssIovBufferDesc,
  iovCount:  cint
): GssUint32 {.importc, dynlib: gssLib.}

proc gss_unwrap_iov(
  minor:     ptr GssUint32,
  ctx:       GssCtxId,
  confState: ptr cint,
  qopState:  ptr GssUint32,
  iov:       ptr GssIovBufferDesc,
  iovCount:  cint
): GssUint32 {.importc, dynlib: gssLib.}

proc gss_release_iov_buffer(
  minor:    ptr GssUint32,
  iov:      ptr GssIovBufferDesc,
  iovCount: cint
): GssUint32 {.importc, dynlib: gssLib.}

proc gssError(major, minor: GssUint32): string =
  var m2: GssUint32
  var ctx: GssUint32 = 0
  var buf = GssBufferDesc(length: 0, value: nil)
  discard gss_display_status(addr m2, major, 1.cint, GSS_C_NO_OID, addr ctx, addr buf)
  if buf.value != nil and buf.length > 0:
    let p = cast[ptr UncheckedArray[byte]](buf.value)
    for i in 0..<int(buf.length): result.add char(p[i])
    discard gss_release_buffer(addr m2, addr buf)
  ctx = 0
  discard gss_display_status(addr m2, minor, 2.cint, GSS_C_NO_OID, addr ctx, addr buf)
  if buf.value != nil and buf.length > 0:
    result.add " — "
    let p = cast[ptr UncheckedArray[byte]](buf.value)
    for i in 0..<int(buf.length): result.add char(p[i])
    discard gss_release_buffer(addr m2, addr buf)
  if result.len == 0:
    result = fmt"major={major} minor={minor}"


proc toLE16(s: string): seq[byte] =
  for c in s:
    result.add byte(ord(c))
    result.add 0x00'u8

proc toLE32(v: uint32): array[4, byte] =
  result[0] = byte(v and 0xFF)
  result[1] = byte((v shr  8) and 0xFF)
  result[2] = byte((v shr 16) and 0xFF)
  result[3] = byte((v shr 24) and 0xFF)

proc toBE32(v: uint32): array[4, byte] =
  result[0] = byte((v shr 24) and 0xFF)
  result[1] = byte((v shr 16) and 0xFF)
  result[2] = byte((v shr 8) and 0xFF)
  result[3] = byte(v and 0xFF)

proc toBE64(v: uint64): array[8, byte] =
  for i in 0..7:
    result[i] = byte((v shr ((7 - i) * 8)) and 0xFF)

proc toLE16u(v: uint16): array[2, byte] =
  result[0] = byte(v and 0xFF)
  result[1] = byte((v shr 8) and 0xFF)

proc readLE32(data: openArray[byte], offset: int): uint32 =
  result = uint32(data[offset]) or
           (uint32(data[offset+1]) shl  8) or
           (uint32(data[offset+2]) shl 16) or
           (uint32(data[offset+3]) shl 24)

proc readLE16(data: openArray[byte], offset: int): uint16 =
  result = uint16(data[offset]) or (uint16(data[offset+1]) shl 8)

proc readLE32Str(data: string, offset: int): uint32 =
  result = uint32(ord(data[offset])) or
           (uint32(ord(data[offset + 1])) shl 8) or
           (uint32(ord(data[offset + 2])) shl 16) or
           (uint32(ord(data[offset + 3])) shl 24)

proc hasBytes(data: string, offset, count: int): bool =
  offset >= 0 and count >= 0 and offset <= data.len and count <= data.len - offset

proc readLE16Str(data: string, offset: int): uint16 =
  result = uint16(ord(data[offset])) or (uint16(ord(data[offset + 1])) shl 8)

proc rvaToOffset(data: string, peOffset, rva: int): int =
  if not hasBytes(data, peOffset + 20, 4): return -1
  let sectionCount = int(readLE16Str(data, peOffset + 6))
  let optionalSize = int(readLE16Str(data, peOffset + 20))
  let sectionOffset = peOffset + 24 + optionalSize
  for i in 0..<sectionCount:
    let off = sectionOffset + (i * 40)
    if not hasBytes(data, off, 40): return -1
    let virtualSize = int(readLE32Str(data, off + 8))
    let virtualAddress = int(readLE32Str(data, off + 12))
    let rawSize = int(readLE32Str(data, off + 16))
    let rawPointer = int(readLE32Str(data, off + 20))
    let span = max(virtualSize, rawSize)
    if span > 0 and rva >= virtualAddress and rva < virtualAddress + span:
      let fileOffset = rawPointer + (rva - virtualAddress)
      if hasBytes(data, fileOffset, 1): return fileOffset
      return -1
  result = -1

proc isManagedPe(data: string): bool =
  if not hasBytes(data, 0, 0x40): return false
  if data[0] != 'M' or data[1] != 'Z': return false
  let peOffset = int(readLE32Str(data, 0x3c))
  if not hasBytes(data, peOffset, 24): return false
  if data[peOffset] != 'P' or data[peOffset + 1] != 'E' or data[peOffset + 2] != '\0' or data[peOffset + 3] != '\0':
    return false

  let optionalOffset = peOffset + 24
  if not hasBytes(data, optionalOffset, 2): return false
  let magic = readLE16Str(data, optionalOffset)
  let dataDirectoryOffset =
    case magic
    of 0x10b'u16: optionalOffset + 96
    of 0x20b'u16: optionalOffset + 112
    else: return false

  let clrDirectoryOffset = dataDirectoryOffset + (14 * 8)
  if not hasBytes(data, clrDirectoryOffset, 8): return false
  let clrRva = int(readLE32Str(data, clrDirectoryOffset))
  let clrSize = int(readLE32Str(data, clrDirectoryOffset + 4))
  if clrRva == 0 or clrSize == 0: return false
  result = rvaToOffset(data, peOffset, clrRva) >= 0


proc md4(msg: openArray[byte]): array[16, byte] =
  proc fF(x, y, z: uint32): uint32 = (x and y) or ((not x) and z)
  proc fG(x, y, z: uint32): uint32 = (x and y) or (x and z) or (y and z)
  proc fH(x, y, z: uint32): uint32 = x xor y xor z
  proc rol(x: uint32, n: int): uint32 = (x shl n) or (x shr (32 - n))

  var m: seq[byte]
  for b in msg: m.add b
  let origLen = m.len
  m.add 0x80'u8
  while (m.len mod 64) != 56: m.add 0x00'u8
  let bl = uint64(origLen) * 8
  for i in 0..7: m.add byte((bl shr (i*8)) and 0xFF)

  var A: uint32 = 0x67452301'u32
  var B: uint32 = 0xefcdab89'u32
  var C: uint32 = 0x98badcfe'u32
  var D: uint32 = 0x10325476'u32

  var i = 0
  while i < m.len:
    var X: array[16, uint32]
    for j in 0..15:
      let o = i + j*4
      X[j] = uint32(m[o]) or (uint32(m[o+1]) shl 8) or
             (uint32(m[o+2]) shl 16) or (uint32(m[o+3]) shl 24)
    let AA = A; let BB = B; let CC = C; let DD = D

    let s1 = [3,7,11,19]
    for idx in 0..15:
      let s = s1[idx mod 4]
      case (idx mod 4)
      of 0: A = rol(A + fF(B,C,D) + X[idx], s)
      of 1: D = rol(D + fF(A,B,C) + X[idx], s)
      of 2: C = rol(C + fF(D,A,B) + X[idx], s)
      else: B = rol(B + fF(C,D,A) + X[idx], s)

    let s2  = [3,5,9,13]
    let o2  = [0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15]
    for idx in 0..15:
      let k = o2[idx]; let s = s2[idx mod 4]
      case (idx mod 4)
      of 0: A = rol(A + fG(B,C,D) + X[k] + 0x5A827999'u32, s)
      of 1: D = rol(D + fG(A,B,C) + X[k] + 0x5A827999'u32, s)
      of 2: C = rol(C + fG(D,A,B) + X[k] + 0x5A827999'u32, s)
      else: B = rol(B + fG(C,D,A) + X[k] + 0x5A827999'u32, s)

    let s3  = [3,9,11,15]
    let o3  = [0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15]
    for idx in 0..15:
      let k = o3[idx]; let s = s3[idx mod 4]
      case (idx mod 4)
      of 0: A = rol(A + fH(B,C,D) + X[k] + 0x6ED9EBA1'u32, s)
      of 1: D = rol(D + fH(A,B,C) + X[k] + 0x6ED9EBA1'u32, s)
      of 2: C = rol(C + fH(D,A,B) + X[k] + 0x6ED9EBA1'u32, s)
      else: B = rol(B + fH(C,D,A) + X[k] + 0x6ED9EBA1'u32, s)

    A += AA; B += BB; C += CC; D += DD
    i += 64

  for idx in 0..3: result[idx]    = byte((A shr (idx*8)) and 0xFF)
  for idx in 0..3: result[4+idx]  = byte((B shr (idx*8)) and 0xFF)
  for idx in 0..3: result[8+idx]  = byte((C shr (idx*8)) and 0xFF)
  for idx in 0..3: result[12+idx] = byte((D shr (idx*8)) and 0xFF)


proc md5(data: openArray[byte]): array[16, byte] =
  const T: array[64, uint32] = [
    0xd76aa478'u32, 0xe8c7b756'u32, 0x242070db'u32, 0xc1bdceee'u32,
    0xf57c0faf'u32, 0x4787c62a'u32, 0xa8304613'u32, 0xfd469501'u32,
    0x698098d8'u32, 0x8b44f7af'u32, 0xffff5bb1'u32, 0x895cd7be'u32,
    0x6b901122'u32, 0xfd987193'u32, 0xa679438e'u32, 0x49b40821'u32,
    0xf61e2562'u32, 0xc040b340'u32, 0x265e5a51'u32, 0xe9b6c7aa'u32,
    0xd62f105d'u32, 0x02441453'u32, 0xd8a1e681'u32, 0xe7d3fbc8'u32,
    0x21e1cde6'u32, 0xc33707d6'u32, 0xf4d50d87'u32, 0x455a14ed'u32,
    0xa9e3e905'u32, 0xfcefa3f8'u32, 0x676f02d9'u32, 0x8d2a4c8a'u32,
    0xfffa3942'u32, 0x8771f681'u32, 0x6d9d6122'u32, 0xfde5380c'u32,
    0xa4beea44'u32, 0x4bdecfa9'u32, 0xf6bb4b60'u32, 0xbebfbc70'u32,
    0x289b7ec6'u32, 0xeaa127fa'u32, 0xd4ef3085'u32, 0x04881d05'u32,
    0xd9d4d039'u32, 0xe6db99e5'u32, 0x1fa27cf8'u32, 0xc4ac5665'u32,
    0xf4292244'u32, 0x432aff97'u32, 0xab9423a7'u32, 0xfc93a039'u32,
    0x655b59c3'u32, 0x8f0ccc92'u32, 0xffeff47d'u32, 0x85845dd1'u32,
    0x6fa87e4f'u32, 0xfe2ce6e0'u32, 0xa3014314'u32, 0x4e0811a1'u32,
    0xf7537e82'u32, 0xbd3af235'u32, 0x2ad7d2bb'u32, 0xeb86d391'u32
  ]
  const S: array[64, uint32] = [
    7'u32,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
    5,9,14,20,      5,9,14,20,  5,9,14,20,  5,9,14,20,
    4,11,16,23,     4,11,16,23, 4,11,16,23, 4,11,16,23,
    6,10,15,21,     6,10,15,21, 6,10,15,21, 6,10,15,21
  ]

  proc rol32(x, n: uint32): uint32 = (x shl n) or (x shr (32'u32 - n))

  var m: seq[byte]
  for b in data: m.add b
  let origLen = m.len
  m.add 0x80'u8
  while (m.len mod 64) != 56: m.add 0x00'u8
  let bl = uint64(origLen) * 8
  for i in 0..7: m.add byte((bl shr (i*8)) and 0xFF)

  var a0: uint32 = 0x67452301'u32
  var b0: uint32 = 0xefcdab89'u32
  var c0: uint32 = 0x98badcfe'u32
  var d0: uint32 = 0x10325476'u32

  var i = 0
  while i < m.len:
    var M: array[16, uint32]
    for j in 0..15:
      let o = i + j*4
      M[j] = uint32(m[o]) or (uint32(m[o+1]) shl 8) or
             (uint32(m[o+2]) shl 16) or (uint32(m[o+3]) shl 24)
    var a = a0; var b = b0; var c = c0; var d = d0
    for j in 0..63:
      var F: uint32
      var g: int
      if j < 16:
        F = (b and c) or ((not b) and d); g = j
      elif j < 32:
        F = (d and b) or ((not d) and c); g = (5*j + 1) mod 16
      elif j < 48:
        F = b xor c xor d; g = (3*j + 5) mod 16
      else:
        F = c xor (b or (not d)); g = (7*j) mod 16
      F = F + a + T[j] + M[g]
      a = d; d = c; c = b
      b = b + rol32(F, S[j])
    a0 += a; b0 += b; c0 += c; d0 += d
    i += 64

  for idx in 0..3: result[idx]    = byte((a0 shr (idx*8)) and 0xFF)
  for idx in 0..3: result[4+idx]  = byte((b0 shr (idx*8)) and 0xFF)
  for idx in 0..3: result[8+idx]  = byte((c0 shr (idx*8)) and 0xFF)
  for idx in 0..3: result[12+idx] = byte((d0 shr (idx*8)) and 0xFF)

proc hmacMd5(key, data: openArray[byte]): array[16, byte] =
  var k: array[64, byte]
  if key.len > 64:
    let h = md5(key)
    for i in 0..15: k[i] = h[i]
  else:
    for i in 0..<key.len: k[i] = key[i]
  var ipad, opad: array[64, byte]
  for i in 0..63:
    ipad[i] = k[i] xor 0x36'u8
    opad[i] = k[i] xor 0x5c'u8
  var inner = newSeq[byte](64 + data.len)
  for i in 0..63: inner[i] = ipad[i]
  for i, b in data: inner[64+i] = b
  let ih = md5(inner)
  var outer = newSeq[byte](80)
  for i in 0..63: outer[i] = opad[i]
  for i in 0..15: outer[64+i] = ih[i]
  result = md5(outer)

proc hexNibble(c: char): int =
  case c
  of '0'..'9': ord(c) - ord('0')
  of 'a'..'f': ord(c) - ord('a') + 10
  of 'A'..'F': ord(c) - ord('A') + 10
  else: -1

proc parseNtHash(hashSpec: string): array[16, byte] =
  var h = hashSpec.strip()
  if ":" in h:
    h = h.split(':')[^1].strip()
  h = h.replace(" ", "")
  if h.len != 32:
    raise newException(ValueError, "NT hash must be 32 hex chars, or LM:NT")
  for i in 0..<16:
    let hi = hexNibble(h[i * 2])
    let lo = hexNibble(h[i * 2 + 1])
    if hi < 0 or lo < 0:
      raise newException(ValueError, "NT hash contains non-hex characters")
    result[i] = byte((hi shl 4) or lo)


const
  NTLM_SIG    = "NTLMSSP\x00"
  NTLM_FLAGS  = 0x60088215'u32

proc buildNtlmNegotiate(): string =
  var msg: seq[byte]
  for c in NTLM_SIG: msg.add byte(ord(c))
  let t = toLE32(1'u32); msg.add t
  let f = toLE32(NTLM_FLAGS); msg.add f
  for _ in 0..1:
    msg.add 0'u8; msg.add 0'u8   # length
    msg.add 0'u8; msg.add 0'u8   # maxLen
    msg.add 0x28'u8; msg.add 0'u8; msg.add 0'u8; msg.add 0'u8
  msg.add [0x06'u8,0x01,0x00,0x00,0x00,0x00,0x00,0x0f]
  result = cast[string](msg)

type NtlmChallenge = object
  serverChallenge: array[8, byte]
  targetName:      string

proc parseChallenge(raw: seq[byte]): NtlmChallenge =
  let sig = cast[string](raw[0..7])
  if sig != NTLM_SIG:
    raise newException(ValueError, "Bad NTLM challenge signature")
  let msgType = readLE32(raw, 8)
  if msgType != 2:
    raise newException(ValueError, "Expected NTLM type 2")
  let tnLen    = int(readLE16(raw, 12))
  let tnOffset = int(readLE32(raw, 16))
  var tn16: string
  for i in 0..<tnLen: tn16.add char(raw[tnOffset+i])
  var tn: string
  var i = 0
  while i + 1 < tn16.len:
    if tn16[i] != '\x00': tn.add tn16[i]
    i += 2
  result.targetName = tn
  for i in 0..7: result.serverChallenge[i] = raw[24+i]

proc buildNtlmAuthenticate(
  username, password, domain, workstation, ntHashHex: string,
  chall: NtlmChallenge
): string =
  let nh = if ntHashHex != "": parseNtHash(ntHashHex) else: md4(toLE16(password))

  var cc: array[8, byte]
  for i in 0..7: cc[i] = byte(rand(255))

  let epoch = getTime().toUnix()
  let wt    = uint64(epoch) * 10_000_000'u64 + 116_444_736_000_000_000'u64
  var ts: array[8, byte]
  for i in 0..7: ts[i] = byte((wt shr (i*8)) and 0xFF)

  let utd   = toLE16(username.toUpperAscii() & domain)
  let nhKey = hmacMd5(nh, utd)

  var blob: seq[byte]
  blob.add [0x01'u8,0x01,0x00,0x00,0x00,0x00,0x00,0x00]
  blob.add ts
  blob.add cc
  blob.add [0x00'u8,0x00,0x00,0x00]
  let tnb = toLE16(domain)
  blob.add [0x02'u8,0x00]
  let tnbLen = toLE16u(uint16(tnb.len))
  blob.add tnbLen[0]; blob.add tnbLen[1]
  blob.add tnb
  blob.add [0x00'u8,0x00,0x00,0x00]

  var challData: seq[byte]
  challData.add chall.serverChallenge
  challData.add blob
  let ntProof = hmacMd5(nhKey, challData)

  var ntResp: seq[byte]
  ntResp.add ntProof
  ntResp.add blob

  var lmResp = newSeq[byte](24)

  let domB  = toLE16(domain)
  let userB = toLE16(username)
  let wsB   = toLE16(workstation)

  let baseOff: uint32 = 88  # 8+4+4 + 6*8 + 8 = 88
  var payload: seq[byte]
  var offs: array[6, uint32]

  offs[0] = baseOff + uint32(payload.len); payload.add lmResp
  offs[1] = baseOff + uint32(payload.len); payload.add ntResp
  offs[2] = baseOff + uint32(payload.len); payload.add domB
  offs[3] = baseOff + uint32(payload.len); payload.add userB
  offs[4] = baseOff + uint32(payload.len); payload.add wsB
  offs[5] = baseOff + uint32(payload.len)  # empty session key

  var msg: seq[byte]
  for c in NTLM_SIG: msg.add byte(ord(c))
  let t = toLE32(3'u32); msg.add t

  proc addSB(data: seq[byte], off: uint32) =
    let ln = toLE16u(uint16(data.len))
    let o4 = toLE32(off)
    msg.add ln[0]; msg.add ln[1]
    msg.add ln[0]; msg.add ln[1]
    msg.add o4[0]; msg.add o4[1]; msg.add o4[2]; msg.add o4[3]

  addSB(lmResp, offs[0])
  addSB(ntResp, offs[1])
  addSB(domB,   offs[2])
  addSB(userB,  offs[3])
  addSB(wsB,    offs[4])
  addSB(@[],    offs[5])

  let flags = toLE32(NTLM_FLAGS); msg.add flags
  msg.add [0x06'u8,0x01,0x00,0x00,0x00,0x00,0x00,0x0f]
  for _ in 0..15: msg.add 0x00'u8  # MIC
  msg.add payload
  result = cast[string](msg)


proc importSpn(host, realm, spnOverride: string): GssNameT =
  var minor: GssUint32

  let explicitSpn = spnOverride.strip()
  if explicitSpn != "":
    var ibufExplicit = GssBufferDesc(length: csize_t(explicitSpn.len), value: cstring(explicitSpn))
    var impExplicit = gss_import_name(addr minor, addr ibufExplicit, GSS_C_NO_OID, addr result)
    if impExplicit == GSS_S_COMPLETE:
      if getEnv("WINRMSHELL_DEBUG") == "1":
        styledEcho(fgYellow, "[*] importSpn: imported override " & explicitSpn & " as explicit principal")
      return result

    var svcElemsExplicit: array[6, byte] = [0x2b'u8, 0x06, 0x01, 0x05, 0x06, 0x02]
    var svcDescExplicit = GssOidDesc(length: 6, elements: addr svcElemsExplicit[0])
    ibufExplicit = GssBufferDesc(length: csize_t(explicitSpn.len), value: cstring(explicitSpn))
    impExplicit = gss_import_name(addr minor, addr ibufExplicit, addr svcDescExplicit, addr result)
    if impExplicit == GSS_S_COMPLETE:
      if getEnv("WINRMSHELL_DEBUG") == "1":
        styledEcho(fgYellow, "[*] importSpn: imported override " & explicitSpn & " as host-based service")
      return result
    raise newException(OSError, "gss_import_name failed for SPN override " & explicitSpn & ": " & gssError(impExplicit, minor))

  var hostOnly = host.strip()
  if hostOnly.len > 0 and hostOnly[hostOnly.len-1] == '.':
    hostOnly = hostOnly[0..hostOnly.len-2]
  if ':' in hostOnly:
    hostOnly = hostOnly.split(':')[0]
  hostOnly = hostOnly.toLowerAscii()

  var realmNorm = realm.strip()
  if realmNorm.len > 0:
    realmNorm = realmNorm.toUpperAscii()

  var krbPrincipalElems: array[10, byte] = [0x2a'u8, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, 0x01]
  var krbPrincipalDesc  = GssOidDesc(length: 10, elements: addr krbPrincipalElems[0])
  var svcElems: array[6, byte] = [0x2b'u8, 0x06, 0x01, 0x05, 0x06, 0x02]
  var svcDesc  = GssOidDesc(length: 6, elements: addr svcElems[0])

  var lastMaj: GssUint32 = 0
  var lastMin: GssUint32 = 0
  var chosenSpn = ""

  if realmNorm != "":
    chosenSpn = "HTTP/" & hostOnly & "@" & realmNorm
    var ibufRealm = GssBufferDesc(length: csize_t(chosenSpn.len), value: cstring(chosenSpn))
    let impRealm = gss_import_name(addr minor, addr ibufRealm, GSS_C_NO_OID, addr result)
    if impRealm == GSS_S_COMPLETE:
      if getEnv("WINRMSHELL_DEBUG") == "1":
        styledEcho(fgYellow, "[*] importSpn: imported " & chosenSpn & " as KRB5 principal (with realm)")
      return result
    else:
      if lastMaj == 0: lastMaj = impRealm; lastMin = minor

  chosenSpn = "HTTP/" & hostOnly
  var ibufSlash = GssBufferDesc(length: csize_t(chosenSpn.len), value: cstring(chosenSpn))
  let impSlash = gss_import_name(addr minor, addr ibufSlash, addr svcDesc, addr result)
  if impSlash == GSS_S_COMPLETE:
    if getEnv("WINRMSHELL_DEBUG") == "1":
      styledEcho(fgYellow, "[*] importSpn: imported " & chosenSpn & " as host-based service (svcDesc)")
    return result
  else:
    if lastMaj == 0: lastMaj = impSlash; lastMin = minor

  chosenSpn = "HTTP/" & hostOnly
  var ibufOld = GssBufferDesc(length: csize_t(chosenSpn.len), value: cstring(chosenSpn))
  let impOld = gss_import_name(addr minor, addr ibufOld, addr krbPrincipalDesc, addr result)
  if impOld == GSS_S_COMPLETE:
    if getEnv("WINRMSHELL_DEBUG") == "1":
      styledEcho(fgYellow, "[*] importSpn: imported " & chosenSpn & " as Kerberos principal without realm")
    return result
  else:
    if lastMaj == 0: lastMaj = impOld; lastMin = minor

  chosenSpn = "HTTP@" & hostOnly
  var ibufAt = GssBufferDesc(length: csize_t(chosenSpn.len), value: cstring(chosenSpn))
  let impAt = gss_import_name(addr minor, addr ibufAt, addr svcDesc, addr result)
  if impAt == GSS_S_COMPLETE:
    if getEnv("WINRMSHELL_DEBUG") == "1":
      styledEcho(fgYellow, "[*] importSpn: imported " & chosenSpn & " as host-based service (svcDesc)")
    return result
  else:
    if lastMaj == 0: lastMaj = impAt; lastMin = minor

  if getEnv("WINRMSHELL_DEBUG") == "1":
    styledEcho(fgRed, "[*] importSpn: failed attempts, last error: " & gssError(if lastMaj != 0: lastMaj else: impAt, if lastMaj != 0: lastMin else: minor))

  raise newException(OSError, "gss_import_name failed: " & gssError(if lastMaj != 0: lastMaj else: impAt, if lastMaj != 0: lastMin else: minor))


proc wrapSoap(ctx: GssCtxId, soap: string): string =
  const
    GSS_IOV_BUFFER_TYPE_DATA = 1'u32
    GSS_IOV_BUFFER_TYPE_HEADER = 2'u32
    GSS_IOV_BUFFER_TYPE_PADDING = 9'u32
    GSS_IOV_BUFFER_FLAG_ALLOCATE = 0x10000'u32

  var minor: GssUint32
  var soapCopy = soap
  var iov: array[3, GssIovBufferDesc]
  iov[0].typ = GSS_IOV_BUFFER_TYPE_HEADER or GSS_IOV_BUFFER_FLAG_ALLOCATE
  iov[1].typ = GSS_IOV_BUFFER_TYPE_DATA
  iov[1].buffer = GssBufferDesc(
    length: csize_t(soapCopy.len),
    value:  if soapCopy.len > 0: cast[pointer](addr soapCopy[0]) else: nil)
  iov[2].typ = GSS_IOV_BUFFER_TYPE_PADDING or GSS_IOV_BUFFER_FLAG_ALLOCATE

  var confSt: cint = 0
  let maj = gss_wrap_iov(addr minor, ctx, 1.cint, 0'u32, addr confSt, addr iov[0], 3.cint)
  if maj != GSS_S_COMPLETE:
    raise newException(OSError, "gss_wrap_iov failed: " & gssError(maj, minor))

  var frame = ""
  let headerLen = uint32(iov[0].buffer.length)
  for b in toLE32(headerLen): frame.add char(b)
  if iov[0].buffer.value != nil and iov[0].buffer.length > 0:
    let p = cast[ptr UncheckedArray[byte]](iov[0].buffer.value)
    for i in 0..<int(iov[0].buffer.length): frame.add char(p[i])
  if iov[1].buffer.value != nil and iov[1].buffer.length > 0:
    let p = cast[ptr UncheckedArray[byte]](iov[1].buffer.value)
    for i in 0..<int(iov[1].buffer.length): frame.add char(p[i])
  if iov[2].buffer.value != nil and iov[2].buffer.length > 0:
    let p = cast[ptr UncheckedArray[byte]](iov[2].buffer.value)
    for i in 0..<int(iov[2].buffer.length): frame.add char(p[i])
  let originalLen = soap.len + int(iov[2].buffer.length)

  discard gss_release_iov_buffer(addr minor, addr iov[0], 3.cint)

  result =
    "--Encrypted Boundary\r\n" &
    "Content-Type: application/HTTP-Kerberos-session-encrypted\r\n" &
    "OriginalContent: type=application/soap+xml;charset=UTF-8;Length=" & $originalLen & "\r\n" &
    "--Encrypted Boundary\r\n" &
    "Content-Type: application/octet-stream\r\n" &
    frame &
    "--Encrypted Boundary--\r\n"

proc unwrapResponse(ctx: GssCtxId, body: string): string =
  const
    GSS_IOV_BUFFER_TYPE_DATA = 1'u32
    GSS_IOV_BUFFER_TYPE_HEADER = 2'u32

  const octetMarker = "application/octet-stream"
  let octetIdx = body.find(octetMarker)
  if octetIdx < 0: return body

  var originalLen = -1
  let ocIdx = body.find("OriginalContent:")
  if ocIdx >= 0 and ocIdx < octetIdx:
    let lenIdx = body.find("Length=", ocIdx)
    if lenIdx >= 0 and lenIdx < octetIdx:
      var pos = lenIdx + "Length=".len
      var digits: string
      while pos < body.len and body[pos] in {'0'..'9'}:
        digits.add body[pos]
        inc pos
      if digits.len > 0:
        try: originalLen = parseInt(digits)
        except: originalLen = -1

  var dataStart = octetIdx + octetMarker.len
  
  let marker = "\r\n"
  let bodyStart = body.find(marker, dataStart)
  if bodyStart < 0: return body
  dataStart = bodyStart + marker.len
  
  let endMark = "\r\n--Encrypted Boundary"
  var binEnd  = body.find(endMark, dataStart)
  if binEnd < 0:
    binEnd = body.find("\n--Encrypted Boundary", dataStart)
  if binEnd < 0:
    binEnd = body.find("--Encrypted Boundary", dataStart)
  if binEnd < 0: binEnd = body.len
  
  if binEnd <= dataStart + 4: return body

  let headerLen = int(uint32(ord(body[dataStart])) or
                      (uint32(ord(body[dataStart + 1])) shl 8) or
                      (uint32(ord(body[dataStart + 2])) shl 16) or
                      (uint32(ord(body[dataStart + 3])) shl 24))
  let headerStart = dataStart + 4
  let dataPartStart = headerStart + headerLen
  if dataPartStart > binEnd: return body
  if originalLen >= 0 and dataPartStart + originalLen <= body.len:
    binEnd = dataPartStart + originalLen

  var headerBytes = body[headerStart..<dataPartStart]
  var encBytes = body[dataPartStart..<binEnd]
  var minor: GssUint32
  var iov: array[3, GssIovBufferDesc]
  iov[0].typ = GSS_IOV_BUFFER_TYPE_HEADER
  iov[0].buffer = GssBufferDesc(
    length: csize_t(headerBytes.len),
    value: if headerBytes.len > 0: cast[pointer](addr headerBytes[0]) else: nil)
  iov[1].typ = GSS_IOV_BUFFER_TYPE_DATA
  iov[1].buffer = GssBufferDesc(
    length: csize_t(encBytes.len),
    value: if encBytes.len > 0: cast[pointer](addr encBytes[0]) else: nil)
  iov[2].typ = GSS_IOV_BUFFER_TYPE_DATA
  var confSt: cint = 0
  var qopSt:  GssUint32 = 0
  let maj = gss_unwrap_iov(addr minor, ctx, addr confSt, addr qopSt, addr iov[0], 3.cint)
  if maj != GSS_S_COMPLETE:
    raise newException(OSError, "gss_unwrap_iov failed: " & gssError(maj, minor))
  
  if iov[1].buffer.value != nil and iov[1].buffer.length > 0:
    let p = cast[ptr UncheckedArray[byte]](iov[1].buffer.value)
    for i in 0..<int(iov[1].buffer.length): result.add char(p[i])


proc genUuid(): string =
  var b: array[16, byte]
  for i in 0..15: b[i] = byte(rand(255))
  b[6] = (b[6] and 0x0F) or 0x40
  b[8] = (b[8] and 0x3F) or 0x80
  result = fmt"{b[0]:02x}{b[1]:02x}{b[2]:02x}{b[3]:02x}-" &
           fmt"{b[4]:02x}{b[5]:02x}-{b[6]:02x}{b[7]:02x}-" &
           fmt"{b[8]:02x}{b[9]:02x}-" &
           fmt"{b[10]:02x}{b[11]:02x}{b[12]:02x}{b[13]:02x}{b[14]:02x}{b[15]:02x}"

proc xmlEscape(s: string): string =
  for c in s:
    case c
    of '&': result.add "&amp;"
    of '<': result.add "&lt;"
    of '>': result.add "&gt;"
    of '"': result.add "&quot;"
    of '\'': result.add "&apos;"
    else: result.add c

proc uuidToPsrpBytes(uuid: string): seq[byte] =
  let h = uuid.replace("-", "")
  if h.len != 32:
    for _ in 0..<16: result.add 0'u8
    return
  var raw: array[16, byte]
  for i in 0..<16:
    raw[i] = byte(parseHexInt(h[i * 2 .. i * 2 + 1]))
  for i in [3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15]:
    result.add raw[i]

proc psrpMessage(runspaceId, pipelineId: string, msgType: uint32, data: string): seq[byte] =
  for b in toLE32(2'u32): result.add b
  for b in toLE32(msgType): result.add b
  result.add uuidToPsrpBytes(runspaceId)
  result.add uuidToPsrpBytes(pipelineId)
  result.add [0xEF'u8, 0xBB, 0xBF]
  for c in data: result.add byte(ord(c))

proc psrpFragment(objectId: uint64, blob: seq[byte]): seq[byte] =
  for b in toBE64(objectId): result.add b
  for b in toBE64(0'u64): result.add b
  result.add 0x03'u8
  for b in toBE32(uint32(blob.len)): result.add b
  result.add blob

proc sessionCapabilityXml(): string =
  """<Obj RefId="0"><MS><Version N="protocolversion">2.3</Version><Version N="PSVersion">2.0</Version><Version N="SerializationVersion">1.1.0.1</Version></MS></Obj>"""

proc initRunspaceXml(): string =
  """<Obj RefId="0"><MS><I32 N="MinRunspaces">1</I32><I32 N="MaxRunspaces">1</I32><Obj N="PSThreadOptions" RefId="1"><TN RefId="0"><T>System.Management.Automation.Runspaces.PSThreadOptions</T><T>System.Enum</T><T>System.ValueType</T><T>System.Object</T></TN><ToString>Default</ToString><I32>0</I32></Obj><Obj N="ApartmentState" RefId="2"><TN RefId="1"><T>System.Threading.ApartmentState</T><T>System.Enum</T><T>System.ValueType</T><T>System.Object</T></TN><ToString>Unknown</ToString><I32>2</I32></Obj><Obj N="ApplicationArguments" RefId="3"><TN RefId="2"><T>System.Management.Automation.PSPrimitiveDictionary</T><T>System.Collections.Hashtable</T><T>System.Object</T></TN><DCT><En><S N="Key">PSVersionTable</S><Obj N="Value" RefId="4"><TNRef RefId="2" /><DCT><En><S N="Key">PSVersion</S><Version N="Value">5.0.11082.1000</Version></En><En><S N="Key">PSRemotingProtocolVersion</S><Version N="Value">2.3</Version></En><En><S N="Key">SerializationVersion</S><Version N="Value">1.1.0.1</Version></En></DCT></Obj></En></DCT></Obj><Obj N="HostInfo" RefId="5"><MS><B N="_isHostNull">true</B><B N="_isHostUINull">true</B><B N="_isHostRawUINull">true</B><B N="_useRunspaceHost">true</B></MS></Obj></MS></Obj>"""

proc pipelineXml(command: string): string =
  let cmd = xmlEscape(command & "\r\nif (!$?) { if($LASTEXITCODE) { exit $LASTEXITCODE } else { exit 1 } }")
  fmt"""<Obj RefId="0"><MS><Obj N="PowerShell" RefId="1"><MS><Obj N="Cmds" RefId="2"><TN RefId="0"><T>System.Collections.Generic.List`1[[System.Management.Automation.PSObject, System.Management.Automation, Version=3.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]]</T><T>System.Object</T></TN><LST><Obj RefId="3"><MS><S N="Cmd">Invoke-expression</S><B N="IsScript">false</B><Nil N="UseLocalScope" /><Obj N="MergeMyResult" RefId="4"><TN RefId="1"><T>System.Management.Automation.Runspaces.PipelineResultTypes</T><T>System.Enum</T><T>System.ValueType</T><T>System.Object</T></TN><ToString>None</ToString><I32>0</I32></Obj><Obj N="MergeToResult" RefId="5"><TNRef RefId="1" /><ToString>None</ToString><I32>0</I32></Obj><Obj N="MergePreviousResults" RefId="6"><TNRef RefId="1" /><ToString>None</ToString><I32>0</I32></Obj><Obj N="MergeError" RefId="7"><TNRef RefId="1" /><ToString>None</ToString><I32>0</I32></Obj><Obj N="MergeWarning" RefId="8"><TNRef RefId="1" /><ToString>None</ToString><I32>0</I32></Obj><Obj N="MergeVerbose" RefId="9"><TNRef RefId="1" /><ToString>None</ToString><I32>0</I32></Obj><Obj N="MergeDebug" RefId="10"><TNRef RefId="1" /><ToString>None</ToString><I32>0</I32></Obj><Obj N="Args" RefId="11"><TNRef RefId="0" /><LST><Obj RefId="12"><MS><S N="N">-Command</S><Nil N="V" /></MS></Obj><Obj RefId="13"><MS><Nil N="N" /><S N="V">{cmd}</S></MS></Obj></LST></Obj></MS></Obj><Obj RefId="14"><MS><S N="Cmd">Out-string</S><B N="IsScript">false</B><Nil N="UseLocalScope" /><Obj N="MergeMyResult" RefId="15"><TNRef RefId="1" /><ToString>None</ToString><I32>0</I32></Obj><Obj N="MergeToResult" RefId="16"><TNRef RefId="1" /><ToString>None</ToString><I32>0</I32></Obj><Obj N="MergePreviousResults" RefId="17"><TNRef RefId="1" /><ToString>None</ToString><I32>0</I32></Obj><Obj N="MergeError" RefId="18"><TNRef RefId="1" /><ToString>None</ToString><I32>0</I32></Obj><Obj N="MergeWarning" RefId="19"><TNRef RefId="1" /><ToString>None</ToString><I32>0</I32></Obj><Obj N="MergeVerbose" RefId="20"><TNRef RefId="1" /><ToString>None</ToString><I32>0</I32></Obj><Obj N="MergeDebug" RefId="21"><TNRef RefId="1" /><ToString>None</ToString><I32>0</I32></Obj><Obj N="Args" RefId="22"><TNRef RefId="0" /><LST><Obj RefId="23"><MS><S N="N">-Stream</S><Nil N="V" /></MS></Obj></LST></Obj></MS></Obj></LST></Obj><B N="IsNested">false</B><Nil N="History" /><B N="RedirectShellErrorOutputPipe">true</B></MS></Obj><B N="NoInput">true</B><Obj N="ApartmentState" RefId="24"><TN RefId="2"><T>System.Threading.ApartmentState</T><T>System.Enum</T><T>System.ValueType</T><T>System.Object</T></TN><ToString>Unknown</ToString><I32>2</I32></Obj><Obj N="RemoteStreamOptions" RefId="25"><TN RefId="3"><T>System.Management.Automation.RemoteStreamOptions</T><T>System.Enum</T><T>System.ValueType</T><T>System.Object</T></TN><ToString>0</ToString><I32>0</I32></Obj><B N="AddToHistory">true</B><Obj N="HostInfo" RefId="26"><MS><B N="_isHostNull">true</B><B N="_isHostUINull">true</B><B N="_isHostRawUINull">true</B><B N="_useRunspaceHost">true</B></MS></Obj><B N="IsNested">false</B></MS></Obj>"""

proc initCreationXml(runspaceId: string): string =
  var bytes: seq[byte]
  bytes.add psrpFragment(1, psrpMessage(runspaceId, "", 0x00010002'u32, sessionCapabilityXml()))
  bytes.add psrpFragment(2, psrpMessage(runspaceId, "", 0x00010004'u32, initRunspaceXml()))
  result = encode(bytes)

proc commandFragment(runspaceId, pipelineId, command: string, objectId: uint64): string =
  let msg = psrpMessage(runspaceId, pipelineId, 0x00021006'u32, pipelineXml(command))
  result = encode(psrpFragment(objectId, msg))

proc encodePs(cmd: string): string =
  var utf16: seq[byte]
  for c in cmd:
    utf16.add byte(ord(c))
    utf16.add 0x00'u8
  result = encode(utf16)

proc soapCreate(host: string, port: int, ssl: bool, runspaceId: string): string =
  let scheme = if ssl: "https" else: "http"
  let url    = fmt"{scheme}://{host}:{port}/wsman"
  let creationXml = initCreationXml(runspaceId)
  fmt"""<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
  xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
  xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
  xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
<s:Header>
  <wsa:To>{url}</wsa:To>
  <wsa:ReplyTo><wsa:Address mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address></wsa:ReplyTo>
  <wsa:Action mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/09/transfer/Create</wsa:Action>
  <wsa:MessageID>uuid:{genUuid()}</wsa:MessageID>
  <wsman:ResourceURI mustUnderstand="true">http://schemas.microsoft.com/powershell/Microsoft.PowerShell</wsman:ResourceURI>
  <wsman:OperationTimeout>PT60.000S</wsman:OperationTimeout>
  <wsman:Locale mustUnderstand="false" xml:lang="en-US"/>
  <wsman:DataLocale mustUnderstand="false" xml:lang="en-US"/>
  <wsman:MaxEnvelopeSize mustUnderstand="true">{WSManMaxEnvelope}</wsman:MaxEnvelopeSize>
  <wsman:OptionSet s:mustUnderstand="true">
    <wsman:Option Name="protocolversion" MustComply="true">2.3</wsman:Option>
  </wsman:OptionSet>
</s:Header>
<s:Body>
  <p:Shell ShellId="{runspaceId}" Name="Runspace">
    <p:InputStreams>stdin pr</p:InputStreams>
    <p:OutputStreams>stdout</p:OutputStreams>
    <creationXml xmlns="http://schemas.microsoft.com/powershell">{creationXml}</creationXml>
  </p:Shell>
</s:Body>
</s:Envelope>"""

proc soapRun(host: string, port: int, ssl: bool, shellId, pipelineId, commandArg: string): string =
  let scheme = if ssl: "https" else: "http"
  let url    = fmt"{scheme}://{host}:{port}/wsman"
  fmt"""<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
  xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
  xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
  xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
<s:Header>
  <wsa:To>{url}</wsa:To>
  <wsa:ReplyTo><wsa:Address mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address></wsa:ReplyTo>
  <wsa:Action mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command</wsa:Action>
  <wsa:MessageID>uuid:{genUuid()}</wsa:MessageID>
  <wsman:ResourceURI mustUnderstand="true">http://schemas.microsoft.com/powershell/Microsoft.PowerShell</wsman:ResourceURI>
  <wsman:SelectorSet><wsman:Selector Name="ShellId">{shellId}</wsman:Selector></wsman:SelectorSet>
  <wsman:OperationTimeout>PT60.000S</wsman:OperationTimeout>
  <wsman:Locale mustUnderstand="false" xml:lang="en-US"/>
  <wsman:DataLocale mustUnderstand="false" xml:lang="en-US"/>
  <wsman:MaxEnvelopeSize mustUnderstand="true">{WSManMaxEnvelope}</wsman:MaxEnvelopeSize>
</s:Header>
<s:Body>
  <p:CommandLine CommandId="{pipelineId}">
    <p:Command>Invoke-Expression</p:Command>
    <p:Arguments>{commandArg}</p:Arguments>
  </p:CommandLine>
</s:Body>
</s:Envelope>"""

proc soapReceive(host: string, port: int, ssl: bool, shellId, cmdId: string): string =
  let scheme = if ssl: "https" else: "http"
  let url    = fmt"{scheme}://{host}:{port}/wsman"
  fmt"""<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
  xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
  xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
  xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
<s:Header>
  <wsa:To>{url}</wsa:To>
  <wsa:ReplyTo><wsa:Address mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address></wsa:ReplyTo>
  <wsa:Action mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive</wsa:Action>
  <wsa:MessageID>uuid:{genUuid()}</wsa:MessageID>
  <wsman:ResourceURI mustUnderstand="true">http://schemas.microsoft.com/powershell/Microsoft.PowerShell</wsman:ResourceURI>
  <wsman:SelectorSet><wsman:Selector Name="ShellId">{shellId}</wsman:Selector></wsman:SelectorSet>
  <wsman:OperationTimeout>PT60.000S</wsman:OperationTimeout>
  <wsman:MaxEnvelopeSize mustUnderstand="true">{WSManMaxEnvelope}</wsman:MaxEnvelopeSize>
</s:Header>
<s:Body>
  <p:Receive><p:DesiredStream CommandId="{cmdId}">stdout</p:DesiredStream></p:Receive>
</s:Body>
</s:Envelope>"""

proc soapKeepAlive(host: string, port: int, ssl: bool, shellId: string): string =
  let scheme = if ssl: "https" else: "http"
  let url    = fmt"{scheme}://{host}:{port}/wsman"
  fmt"""<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
  xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
  xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
  xmlns:p="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">
<s:Header>
  <wsa:To>{url}</wsa:To>
  <wsa:ReplyTo><wsa:Address mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address></wsa:ReplyTo>
  <wsa:Action mustUnderstand="true">http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive</wsa:Action>
  <wsa:MessageID>uuid:{genUuid()}</wsa:MessageID>
  <wsman:ResourceURI mustUnderstand="true">http://schemas.microsoft.com/powershell/Microsoft.PowerShell</wsman:ResourceURI>
  <wsman:SelectorSet><wsman:Selector Name="ShellId">{shellId}</wsman:Selector></wsman:SelectorSet>
  <wsman:OperationTimeout>PT60.000S</wsman:OperationTimeout>
  <wsman:MaxEnvelopeSize mustUnderstand="true">{WSManMaxEnvelope}</wsman:MaxEnvelopeSize>
  <wsman:OptionSet>
    <wsman:Option Name="WSMAN_CMDSHELL_OPTION_KEEPALIVE">TRUE</wsman:Option>
  </wsman:OptionSet>
</s:Header>
<s:Body>
  <p:Receive><p:DesiredStream>stdout</p:DesiredStream></p:Receive>
</s:Body>
</s:Envelope>"""

proc soapDelete(host: string, port: int, ssl: bool, shellId: string): string =
  let scheme = if ssl: "https" else: "http"
  let url    = fmt"{scheme}://{host}:{port}/wsman"
  fmt"""<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
  xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
  xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">
<s:Header>
  <wsa:To>{url}</wsa:To>
  <wsa:ReplyTo><wsa:Address mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:Address></wsa:ReplyTo>
  <wsa:Action mustUnderstand="true">http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete</wsa:Action>
  <wsa:MessageID>uuid:{genUuid()}</wsa:MessageID>
  <wsman:ResourceURI mustUnderstand="true">http://schemas.microsoft.com/powershell/Microsoft.PowerShell</wsman:ResourceURI>
  <wsman:SelectorSet><wsman:Selector Name="ShellId">{shellId}</wsman:Selector></wsman:SelectorSet>
</s:Header>
<s:Body/>
</s:Envelope>"""


proc xmlVal(xml, tag: string): string =
  let open  = "<" & tag
  let close = "</" & tag & ">"
  let si = xml.find(open)
  if si < 0: return ""
  let vi = xml.find('>', si)
  if vi < 0: return ""
  let ei = xml.find(close, vi)
  if ei < 0: return ""
  result = xml[vi+1 ..< ei]

proc xmlAllVals(xml, tag: string): seq[string] =
  let close = "</" & tag & ">"
  var pos = 0
  while true:
    let open = "<" & tag
    let si = xml.find(open, pos)
    if si < 0: break
    let vi = xml.find('>', si)
    if vi < 0: break
    let ei = xml.find(close, vi)
    if ei < 0: break
    result.add xml[vi+1 ..< ei]
    pos = ei + close.len

proc xmlAllValsWithOpen(xml, tag: string): seq[tuple[openTag, value: string]] =
  let close = "</" & tag & ">"
  var pos = 0
  while true:
    let open = "<" & tag
    let si = xml.find(open, pos)
    if si < 0: break
    let vi = xml.find('>', si)
    if vi < 0: break
    let ei = xml.find(close, vi)
    if ei < 0: break
    result.add (xml[si..vi], xml[vi+1 ..< ei])
    pos = ei + close.len

proc decodeStreams(xml: string): string =
  for tag in ["rsp:Stream", "p:Stream", "Stream"]:
    let streams = xmlAllVals(xml, tag)
    for s in streams:
      if s.len > 0:
        try: result.add decode(s)
        except: discard
    if result.len > 0: return

proc extractShellId(xml: string): string =
  for needle in ["<w:Selector Name=\"ShellId\"", "<wsman:Selector Name=\"ShellId\"", "<Selector Name=\"ShellId\""]:
    let si = xml.find(needle)
    if si >= 0:
      let vi = xml.find('>', si)
      let ei = xml.find("</", vi)
      if vi >= 0 and ei > vi:
        return xml[vi+1 ..< ei]
  for tag in ["rsp:ShellId", "ShellId"]:
    result = xmlVal(xml, tag)
    if result != "": return

proc extractCommandId(xml: string): string =
  for tag in ["rsp:CommandId", "CommandId"]:
    result = xmlVal(xml, tag)
    if result != "": return

proc isDone(xml: string): bool =
  var state = xmlVal(xml, "rsp:CommandState")
  if state == "": state = xmlVal(xml, "CommandState")
  result = "Done" in state

proc faultText(xml: string): string =
  for tag in ["s:Text", "f:Message", "p:Message", "Message"]:
    let v = xmlVal(xml, tag)
    if v != "": return v
  let code = xmlVal(xml, "f:WSManFault")
  if code != "": return code
  result = ""


proc wwwAuth(resp: Response): string =
  for key, val in resp.headers:
    if key.toLowerAscii() == "www-authenticate":
      return $val
  result = ""

proc headerVal(resp: Response, name: string): string =
  for key, val in resp.headers:
    if key.toLowerAscii() == name.toLowerAscii():
      return $val
  result = ""

proc debugHttpFailure(whereAt: string, resp: Response) =
  if getEnv("WINRMSHELL_DEBUG") != "1": return
  styledEcho(fgYellow, "[debug] " & whereAt & " HTTP status: " & resp.status)
  let auth = wwwAuth(resp)
  if auth != "":
    styledEcho(fgYellow, "[debug] WWW-Authenticate: " & auth)
  let ctype = headerVal(resp, "content-type")
  if ctype != "":
    styledEcho(fgYellow, "[debug] Content-Type: " & ctype)
  if resp.body.len > 0:
    let preview = resp.body[0..min(300, resp.body.len - 1)]
    styledEcho(fgYellow, "[debug] Body preview: " & preview)


type
  AuthMethod = enum amNtlm, amKerberos

  WinRMClient = object
    host:         string
    username:     string
    password:     string
    ntHash:       string
    spn:          string
    domain:       string
    auth:         AuthMethod
    useSSL:       bool
    port:         int
    shellId:      string
    hc:           HttpClient
    ctx:          GssCtxId
    authenticated: bool
    runspaceId:   string
    nextObjectId: uint64

proc newClient(host, user, pass, ntHash, spn, domain: string,
               auth: AuthMethod, ssl: bool, port: int): WinRMClient =
  result = WinRMClient(host: host, username: user, password: pass,
                       ntHash: ntHash,
                       spn: spn,
                       domain: domain, auth: auth, useSSL: ssl,
                       port: port,
                       hc: newHttpClient(timeout = 60_000),
                       ctx: nil,
                       authenticated: false,
                       runspaceId: "",
                       nextObjectId: 3'u64)

proc baseUrl(c: WinRMClient): string =
  let s = if c.useSSL: "https" else: "http"
  fmt"{s}://{c.host}:{c.port}/wsman"

proc soapHdrs(): HttpHeaders =
  newHttpHeaders({
    "Content-Type": "application/soap+xml;charset=UTF-8",
    "User-Agent":   "nimrm/1.0",
    "Accept":       "*/*",
    "Connection":   "Keep-Alive"
  })

proc doNtlm(c: var WinRMClient, body: string): tuple[status, body: string] =
  let neg = buildNtlmNegotiate()
  var h1  = soapHdrs()
  h1["Authorization"] = "Negotiate " & encode(neg)
  let r1  = c.hc.request(c.baseUrl(), httpMethod = HttpPost, body = body, headers = h1)

  let wa = wwwAuth(r1)
  if wa == "":
    raise newException(IOError, "Server did not send WWW-Authenticate (auth not required?)")

  var challB64: string
  for part in wa.split(','):
    let p = part.strip()
    if p.startsWith("NTLM ") or p.startsWith("Negotiate "):
      challB64 = p.split(' ')[^1]
      break
  if challB64 == "":
    raise newException(IOError, "No NTLM challenge token in: " & wa)

  let challRaw = cast[seq[byte]](decode(challB64))
  let chall    = parseChallenge(challRaw)

  let auth = buildNtlmAuthenticate(c.username, c.password, c.domain, "WINRMSHELL", c.ntHash, chall)
  var h2   = soapHdrs()
  h2["Authorization"] = "Negotiate " & encode(auth)
  let r2 = c.hc.request(c.baseUrl(), httpMethod = HttpPost, body = body, headers = h2)
  result = (r2.status, r2.body)

proc doKerb(c: var WinRMClient, body: string): tuple[status, body: string] =
  var minor: GssUint32
  
  if not c.authenticated:
    var tgt = importSpn(c.host, c.domain, c.spn)

    var obuf = GssBufferDesc(length: 0, value: nil)
    var retf, trec: GssUint32
    let maj1 = gss_init_sec_context(
      addr minor, GSS_C_NO_CREDENTIAL, addr c.ctx,
      tgt, GSS_C_NO_OID, 0x3A'u32, 0, nil,
      nil, nil, addr obuf, addr retf, addr trec)

    if maj1 != GSS_S_COMPLETE and maj1 != GSS_S_CONTINUE_NEEDED:
      var m2: GssUint32; discard gss_release_name(addr m2, addr tgt)
      raise newException(OSError, "gss_init_sec_context failed: " & gssError(maj1, minor))

    var outTok = ""
    if obuf.value != nil and obuf.length > 0:
      let p = cast[ptr UncheckedArray[byte]](obuf.value)
      for i in 0..<int(obuf.length): outTok.add char(p[i])
      discard gss_release_buffer(addr minor, addr obuf)

    var h0 = soapHdrs()
    h0["Authorization"] = "Kerberos " & encode(outTok)
    let r0 = c.hc.request(c.baseUrl(), httpMethod = HttpPost, body = "", headers = h0)
    let wa = wwwAuth(r0)
    var serverTokB64 = ""
    for part in wa.split(','):
      let p = part.strip()
      if p.startsWith("Kerberos ") or p.startsWith("Negotiate "):
        serverTokB64 = p.split(' ')[^1]
        break
    if serverTokB64 == "":
      debugHttpFailure("Kerberos bootstrap", r0)
      var m2: GssUint32; discard gss_release_name(addr m2, addr tgt)
      raise newException(IOError, "Kerberos bootstrap failed: " & r0.status)

    let serverTok = decode(serverTokB64)
    var inBuf = GssBufferDesc(
      length: csize_t(serverTok.len),
      value: if serverTok.len > 0: cast[pointer](unsafeAddr serverTok[0]) else: nil)
    obuf = GssBufferDesc(length: 0, value: nil)
    let maj2 = gss_init_sec_context(
      addr minor, GSS_C_NO_CREDENTIAL, addr c.ctx,
      tgt, GSS_C_NO_OID, 0x3A'u32, 0, nil,
      addr inBuf, nil, addr obuf, addr retf, addr trec)

    var m2: GssUint32; discard gss_release_name(addr m2, addr tgt)
    if obuf.value != nil:
      discard gss_release_buffer(addr minor, addr obuf)
    if maj2 != GSS_S_COMPLETE:
      if maj2 == GSS_S_CONTINUE_NEEDED:
        raise newException(OSError, "gss_init_sec_context needs another Kerberos leg")
      raise newException(OSError, "gss_init_sec_context failed: " & gssError(maj2, minor))

    c.authenticated = true

  var headers = soapHdrs()
  let encBody = wrapSoap(c.ctx, body)
  headers["Content-Type"] = "multipart/encrypted;protocol=\"application/HTTP-Kerberos-session-encrypted\";boundary=\"Encrypted Boundary\""

  let r1 = c.hc.request(c.baseUrl(), httpMethod = HttpPost, body = encBody, headers = headers)

  var respBody = r1.body
  let cTypeHead = r1.headers.getOrDefault("content-type").toLowerAscii()
  
  if "multipart/encrypted" in cTypeHead or "--Encrypted Boundary" in respBody:
    try:
      respBody = unwrapResponse(c.ctx, respBody)
    except CatchableError as e:
      if getEnv("WINRMSHELL_DEBUG") == "1":
        styledEcho(fgYellow, "[debug] unwrapResponse failed: " & e.msg)

  result = (r1.status, respBody)

proc resetTransport(c: var WinRMClient) =
  try: c.hc.close()
  except: discard
  c.hc = newHttpClient(timeout = 60_000)
  c.ctx = nil
  c.authenticated = false

proc isTransportError(e: ref CatchableError): bool =
  let m = e.msg.toLowerAscii()
  result = "connection reset" in m or
           "broken pipe" in m or
           "could not send all data" in m or
           "connection refused" in m or
           "connection closed" in m or
           "socket" in m

proc send(c: var WinRMClient, body: string): string =
  var status, respBody: string
  try:
    (status, respBody) = case c.auth
      of amNtlm:     doNtlm(c, body)
      of amKerberos: doKerb(c, body)
  except CatchableError as e:
    if not isTransportError(e):
      raise
    if getEnv("WINRMSHELL_DEBUG") == "1":
      styledEcho(fgYellow, "[debug] transport reset, reopening HTTP/Kerberos session and retrying request: " & e.msg)
    resetTransport(c)
    (status, respBody) = case c.auth
      of amNtlm:     doNtlm(c, body)
      of amKerberos: doKerb(c, body)
  let code = parseInt(status.split(' ')[0])
  if code == 401:
    raise newException(IOError, "Authentication failed (401)")
  if code notin {200, 201, 202}:
    if code == 500 and ("<s:Envelope" in respBody or "<Envelope" in respBody):
      result = respBody
      return
    let preview = if respBody.len > 0: respBody[0..min(400, respBody.len-1)] else: "(empty body)"
    raise newException(IOError, fmt"WinRM error {code}: " & preview)
  result = respBody

proc waitRunspace(c: var WinRMClient)

proc createShell(c: var WinRMClient): string =
  if c.runspaceId == "":
    c.runspaceId = genUuid().toUpperAscii()
  let xml = c.send(soapCreate(c.host, c.port, c.useSSL, c.runspaceId))
  result  = extractShellId(xml)
  if result == "":
    raise newException(IOError, "Could not find ShellId in:\n" & xml[0..min(2000,xml.len-1)])
  c.shellId = result
  waitRunspace(c)

proc psrpTextValue(v: string): string =
  result = v.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&").replace("&quot;", "\"").replace("&apos;", "'")
  if result.startsWith("\xEF\xBB\xBF"):
    result = result[3..^1]
  result = result.replace("_x000D__x000A_", "\n").replace("_x000A_", "\n").replace("_x000D_", "\n").replace("_x0009_", "\t")

proc isPsrpInternalText(text: string): bool =
  result = text == "" or
           "CallSite.Target" in text or
           "System.Runtime.CompilerServices" in text or
           "System.Management.Automation.Interpreter" in text or
           "InterpretedFrame" in text or
           "Anonymously Hosted DynamicMethods Assembly" in text

proc isPsrpLocationOnly(text: string): bool =
  let t = text.strip()
  result = t.startsWith("At line:") or t.startsWith("+ ") or t.startsWith("CategoryInfo") or t.startsWith("FullyQualifiedErrorId")

proc cleanPsrpErrorText(text: string): string =
  result = text
  let atLine = result.find("\nAt line:")
  if atLine > 0:
    result = result[0..<atLine]
  result = result.strip()
  if isPsrpLocationOnly(result):
    result = ""

proc isPsrpMetadataString(openTag: string): bool =
  result = " N=\"Cmd\"" in openTag or
           " N=\"V\"" in openTag or
           " N=\"N\"" in openTag or
           " N=\"History\"" in openTag

proc decodePsrpText(xml: string): string =
  let streams = xmlAllVals(xml, "rsp:Stream") & xmlAllVals(xml, "p:Stream") & xmlAllVals(xml, "Stream")
  if getEnv("WINRMSHELL_DEBUG") == "1":
    styledEcho(fgYellow, "[debug] PSRP streams: " & $streams.len)
    if streams.len == 0:
      styledEcho(fgYellow, "[debug] Receive preview: " & xml[0..min(500, xml.len - 1)])
  for s in streams:
    if s.len == 0: continue
    var raw: string
    try:
      raw = decode(s)
    except:
      continue
    if raw.len <= 61: continue
    let msgType = readLE32Str(raw, 25)
    if getEnv("WINRMSHELL_DEBUG") == "1":
      styledEcho(fgYellow, "[debug] PSRP msgType=0x" & msgType.toHex(8) & " rawLen=" & $raw.len)
    if msgType != 0x00041004'u32 and msgType != 0x00041005'u32 and msgType != 0x00041006'u32:
      continue
    let data = raw[61..^1]
    if getEnv("WINRMSHELL_DEBUG") == "1":
      styledEcho(fgYellow, "[debug] PSRP data: " & data[0..min(240, data.len - 1)])
    if msgType == 0x00041005'u32:
      let vals = xmlAllValsWithOpen(data, "S")
      var msg = ""
      for item in vals:
        if isPsrpMetadataString(item.openTag):
          continue
        let v = item.value
        let text = psrpTextValue(v)
        if isPsrpInternalText(text) or isPsrpLocationOnly(text):
          continue
        let cleaned = cleanPsrpErrorText(text)
        if cleaned.len > msg.len and not ("System.Management.Automation" in cleaned):
          msg = cleaned
      if msg == "":
        let vals2 = xmlAllVals(data, "ToString")
        if vals2.len > 0:
          let t = psrpTextValue(vals2[0])
          if not isPsrpInternalText(t):
            msg = cleanPsrpErrorText(t)
      if msg.len > 0:
        result.add msg
        result.add "\n"
      continue
    for item in xmlAllValsWithOpen(data, "S"):
      if isPsrpMetadataString(item.openTag):
        continue
      let text = psrpTextValue(item.value)
      if isPsrpInternalText(text) or isPsrpLocationOnly(text):
        continue
      result.add text
      result.add "\n"
    for v in xmlAllVals(data, "ToString"):
      let text = psrpTextValue(v)
      if isPsrpInternalText(text) or isPsrpLocationOnly(text):
        continue
      result.add text
      result.add "\n"

proc psrpRunspaceOpened(xml: string): bool =
  let streams = xmlAllVals(xml, "rsp:Stream") & xmlAllVals(xml, "p:Stream") & xmlAllVals(xml, "Stream")
  for s in streams:
    var raw: string
    try:
      raw = decode(s)
    except:
      continue
    if raw.len <= 61: continue
    let msgType = readLE32Str(raw, 25)
    if msgType != 0x00021005'u32: continue
    let data = raw[61..^1]
    if "<I32>2</I32>" in data or "<I32 N=\"RunspaceState\">2</I32>" in data:
      return true

proc psrpPipelineDone(xml: string): bool =
  let streams = xmlAllVals(xml, "rsp:Stream") & xmlAllVals(xml, "p:Stream") & xmlAllVals(xml, "Stream")
  for s in streams:
    var raw: string
    try:
      raw = decode(s)
    except:
      continue
    if raw.len <= 61: continue
    let msgType = readLE32Str(raw, 25)
    if msgType != 0x00041006'u32: continue
    let data = raw[61..^1]
    if "<I32 N=\"PipelineState\">4</I32>" in data or "<I32>4</I32>" in data:
      return true

proc waitRunspace(c: var WinRMClient) =
  for _ in 0..<160:
    let xml = c.send(soapKeepAlive(c.host, c.port, c.useSSL, c.shellId))
    discard decodePsrpText(xml)
    if psrpRunspaceOpened(xml): return
    if "faultDetail/TimedOut" in xml or "Code=\"2150858793\"" in xml:
      sleep(50)
      continue
    sleep(50)
  if getEnv("WINRMSHELL_DEBUG") == "1":
    styledEcho(fgYellow, "[debug] Runspace did not report Opened before timeout")

proc firstCommandToken(cmd: string): string =
  var s = cmd.strip()
  if s == "": return ""
  if s[0] in {'"', '\''}:
    let q = s[0]
    let ei = s.find(q, 1)
    if ei > 0: return s[1..<ei]
  let sp = s.find({' ', '\t'})
  if sp > 0: result = s[0..<sp] else: result = s

proc isNativeCommand(cmd: string): bool =
  let tok = firstCommandToken(cmd).toLowerAscii()
  result = tok.endsWith(".exe") or tok.startsWith(".\\") or tok.startsWith("./")

type ChunkCallback = proc(chunk: string)

proc runCmdCollect(c: var WinRMClient, cmd: string, isCmd: bool, onChunk: ChunkCallback = nil, mergeStreams = false): string =
  var actualCmd = if isCmd: "cmd.exe /c " & cmd else: cmd
  if not isCmd:
    if isNativeCommand(cmd):
      actualCmd = "& { " & cmd & " } 2>&1 | ForEach-Object { $_.ToString() }"
    elif mergeStreams:
      actualCmd = cmd & " *>&1"
  let pipelineId = genUuid().toUpperAscii()
  let arg = commandFragment(c.runspaceId, pipelineId, actualCmd, c.nextObjectId)
  inc c.nextObjectId
  let cmdXml  = c.send(soapRun(c.host, c.port, c.useSSL, c.shellId, pipelineId, arg))
  if getEnv("WINRMSHELL_DEBUG") == "1":
    styledEcho(fgYellow, "[debug] Command response: " & cmdXml[0..min(1000, cmdXml.len - 1)])
  let cmdId   = extractCommandId(cmdXml)
  if cmdId == "":
    raise newException(IOError, "Could not get CommandId from: " & cmdXml[0..min(2000,cmdXml.len-1)])

  var output: string
  var retries = 0
  while retries < 240:
    let recvXml = c.send(soapReceive(c.host, c.port, c.useSSL, c.shellId, cmdId))
    let chunk   = decodePsrpText(recvXml)
    if chunk.len > 0:
      output.add chunk
      if onChunk != nil:
        onChunk(chunk)
    if getEnv("WINRMSHELL_DEBUG") == "1" and "fault" in recvXml.toLowerAscii():
      let ft = faultText(recvXml)
      if ft != "":
        styledEcho(fgYellow, "[debug] Fault text: " & ft)
    if isDone(recvXml) or psrpPipelineDone(recvXml): break
    sleep(50)
    inc retries
  result = output

proc runCmd(c: var WinRMClient, cmd: string, isCmd: bool, mergeStreams = false): string =
  result = runCmdCollect(c, cmd, isCmd, nil, mergeStreams)

proc currentRemotePath(c: var WinRMClient): string =
  try:
    result = runCmd(c, "(Get-Location).Path", false).strip()
  except:
    result = ""

proc psQuote(s: string): string =
  "'" & s.replace("'", "''") & "'"

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

proc uploadFile(c: var WinRMClient, args: seq[string]) =
  if args.len < 1 or args.len > 2:
    raise newException(ValueError, "usage: upload <local-file> [remote-file-or-dir]")
  let localPath = if isAbsolute(args[0]): args[0] else: getCurrentDir() / args[0]
  if not fileExists(localPath):
    raise newException(IOError, "local file not found: " & localPath)

  let fileName = extractFilename(localPath)
  let remoteArg = if args.len == 2: args[1] else: ""
  let data = readFile(localPath)
  let setup = remotePathSetup("p", remoteArg, fileName)

  discard runCmd(c, setup & "$dir = Split-Path -Parent $p; if($dir -and -not (Test-Path -LiteralPath $dir)){New-Item -ItemType Directory -Path $dir -Force | Out-Null}; [IO.File]::WriteAllBytes($p, (New-Object byte[] 0))", false)

  var off = 0
  var chunkSize = UploadChunkSize
  drawProgress("upload", 0, data.len)
  while off < data.len:
    let stop = min(off + chunkSize, data.len)
    let b64 = encode(data[off ..< stop])
    let cmd = setup & "$bytes = [Convert]::FromBase64String(" & psQuote(b64) & "); " &
              "$fs = [IO.File]::Open($p, [IO.FileMode]::Append, [IO.FileAccess]::Write); " &
              "try {$fs.Write($bytes, 0, $bytes.Length)} finally {$fs.Close()}"
    try:
      discard runCmd(c, cmd, false)
    except Exception as e:
      if "413" in e.msg and chunkSize > 262144:
        resetTransport(c)
        chunkSize = 262144
        continue
      if "413" in e.msg and chunkSize > 131072:
        resetTransport(c)
        chunkSize = 131072
        continue
      raise
    off = stop
    drawProgress("upload", off, data.len)

  echo ""
  styledEcho(fgGreen, "[+] Uploaded " & $data.len & " bytes from " & localPath)

proc uploadDir(c: var WinRMClient, args: seq[string]) =
  if args.len < 1 or args.len > 2:
    raise newException(ValueError, "usage: upload-dir <local-dir> [remote-dir]")
  let localRoot = absolutePath(if isAbsolute(args[0]): args[0] else: getCurrentDir() / args[0])
  if not dirExists(localRoot):
    raise newException(IOError, "local directory not found: " & localRoot)

  let remoteRoot = if args.len == 2: args[1] else: extractFilename(localRoot)
  var dirs, files: seq[string]
  collectLocalTree(localRoot, dirs, files)

  discard runCmd(c, remotePathSetup("root", remoteRoot, extractFilename(localRoot)) &
                    "if(-not (Test-Path -LiteralPath $root)){New-Item -ItemType Directory -Path $root -Force | Out-Null}", false)

  for d in dirs:
    let rel = localRelPath(d, localRoot)
    let remoteDir = remoteJoin(remoteRoot, rel)
    discard runCmd(c, remotePathSetup("d", remoteDir, "") &
                      "if(-not (Test-Path -LiteralPath $d)){New-Item -ItemType Directory -Path $d -Force | Out-Null}", false)

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

  discard runCmd(c, "$script:" & varName & " = New-Object System.Text.StringBuilder", false)
  var off = 0
  drawProgress("stage-script", 0, b64.len)
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
  let output = runCmd(c, cmd, false)
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
  let output = runCmd(c, cmd, false)
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

  discard runCmd(c, "$script:" & varName & " = New-Object System.Text.StringBuilder", false)

  var off = 0
  drawProgress("stage-mem", 0, b64.len)
  try:
    while off < b64.len:
      let stop = min(off + InMemoryB64ChunkSize, b64.len)
      let chunk = b64[off ..< stop]
      discard runCmd(c, "[void]$script:" & varName & ".Append(" & psQuote(chunk) & ")", false)
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
  let setup = remotePathSetup("p", remotePath, "")
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

  let output = runCmd(c, cmd, false)
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
  let setup = remotePathSetup("p", remoteArg, "")
  let sizeOut = runCmd(c, setup & "if(-not (Test-Path -LiteralPath $p -PathType Leaf)){throw ('remote file not found: ' + $p)}; (Get-Item -LiteralPath $p).Length", false).strip()
  let total = parseInt(sizeOut)

  var b64 = newStringOfCap(((total + 2) div 3) * 4)
  drawProgress("download", 0, total)

  let cmd = setup &
    "if(-not (Test-Path -LiteralPath $p -PathType Leaf)){throw ('remote file not found: ' + $p)}; " &
    "$buf = New-Object byte[] " & $DownloadChunkSize & "; " &
    "$fs = [IO.File]::Open($p, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite); " &
    "try { while(($n = $fs.Read($buf, 0, $buf.Length)) -gt 0) { " &
    "if($n -lt $buf.Length){$tmp = New-Object byte[] $n; [Array]::Copy($buf, $tmp, $n); $part = $tmp} else {$part = $buf}; " &
    "$s = [Convert]::ToBase64String($part); " &
    "for($i = 0; $i -lt $s.Length; $i += 4096){$s.Substring($i, [Math]::Min(4096, $s.Length - $i))} " &
    "} } finally {$fs.Close()}"

  proc collectDownload(chunkText: string) =
    for ch in chunkText:
      if not (ch in {' ', '\t', '\r', '\n'}):
        b64.add ch
    drawProgress("download", min((b64.len * 3) div 4, total), total)

  discard runCmdCollect(c, cmd, false, collectDownload)
  if b64.len == 0:
    raise newException(IOError, "download returned no data")
  let data = decode(b64)
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
  let setup = remotePathSetup("p", remoteArg, "")
  let listCmd = setup &
    "if(-not (Test-Path -LiteralPath $p -PathType Container)){throw ('remote directory not found: ' + $p)}; " &
    "$root = (Resolve-Path -LiteralPath $p).Path; " &
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
  for rawLine in runCmd(c, listCmd, false).splitLines():
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

proc deleteShell(c: var WinRMClient) =
  if c.shellId == "": return
  try: discard c.send(soapDelete(c.host, c.port, c.useSSL, c.shellId))
  except: discard
  c.shellId = ""


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
  -K, --kerb-spn   Kerberos SPN override  (e.g. HTTP/dc1.ping.htb@PING.HTB)
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
    if cc == "" and fileExists("c.roberts.ccache"):
      cc = "FILE:" & absolutePath("c.roberts.ccache")
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
  var firstPromptPath = ""

  try:
    client.shellId = createShell(client)
    firstPromptPath = runCmd(client, "$d = [Environment]::GetFolderPath('MyDocuments'); Set-Location -LiteralPath $d; $d", false).strip()
  except Exception as e:
    styledEcho(fgRed, "[!] Failed to create shell: " & e.msg)
    quit(1)

  if execCommand != "":
    try:
      let isCmd = execCommand.startsWith("!")
      let cmd = if isCmd: execCommand[1..^1].strip() else: execCommand
      let output = runCmd(client, cmd, isCmd)
      if output.len > 0:
        stdout.write(output)
        if not output.endsWith("\n"):
          stdout.write("\n")
        stdout.flushFile()
    except Exception as e:
      styledEcho(fgRed, "[!] Error: " & e.msg)
      deleteShell(client)
      quit(1)
    deleteShell(client)
    quit(0)

  echo ""
  styledEcho(fgWhite, "Type commands below. 'exit'/'quit' to end. Prefix '!' for CMD.")
  echo ""

  var cmdHistory: seq[string] = @[]
  while true:
    let promptPath =
      if firstPromptPath != "":
        let p = firstPromptPath
        firstPromptPath = ""
        p
      else:
        currentRemotePath(client)
    let promptStr = ansiForegroundColorCode(fgCyan) &
                    (if promptPath != "": "PS " & promptPath & "> " else: "PS> ") &
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
      elif verb == "upload":
        uploadFile(client, words[1..^1])
      elif verb == "download":
        downloadFile(client, words[1..^1])
      elif verb == "upload-dir":
        uploadDir(client, words[1..^1])
      elif verb == "download-dir":
        downloadDir(client, words[1..^1])
      elif verb == "invoke-script":
        invokeScript(client, words[1..^1])
      elif verb == "ad-info":
        adInfo(client)
      elif verb == "opsec-check":
        opsecCheck(client)
      elif verb in ["execute-assembly", "exec-assembly"]:
        executeAssembly(client, words[1..^1])
      else:
        let isCmd = line.startsWith("!")
        let cmd = if isCmd: line[1..^1].strip() else: line
        let output = runCmd(client, cmd, isCmd)
        if output.len > 0:
          stdout.write(output)
          if not output.endsWith("\n"):
            stdout.write("\n")
          stdout.flushFile()
    except Exception as e:
      styledEcho(fgRed, "\n[!] Error: " & e.msg)

  styledEcho(fgYellow, "[*] Deleting shell...")
  deleteShell(client)
  styledEcho(fgGreen, "[+] Done. Goodbye!")

main()
