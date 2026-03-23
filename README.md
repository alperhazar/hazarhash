# HazarHash

A data integrity and hashing algorithm built entirely on top of the **Hazar** stream cipher engine, implemented in Free Pascal / Lazarus.

HazarHash produces fixed-size digests (128, 256, or 512 bits) from arbitrary-length input — strings, byte buffers, or files — using `THazarEncryption` as its compression function. No external libraries are required.

---

## Table of Contents

- [Project Structure](#project-structure)
- [Algorithm Design](#algorithm-design)
  - [Initialization Vector](#initialization-vector)
  - [Absorption — Compression Function](#absorption--compression-function)
  - [Padding](#padding)
  - [Finalization — Squeeze](#finalization--squeeze)
  - [Digest Sizes](#digest-sizes)
- [Security Properties](#security-properties)
- [Building](#building)
- [Command-Line Tool](#command-line-tool)
  - [string](#string--hash-a-text-string)
  - [file](#file--hash-a-file)
  - [check](#check--compare-against-a-known-digest)
  - [verify](#verify--batch-verification-from-a-hash-file)
  - [Exit Codes](#exit-codes)
  - [Examples](#examples)
- [API Reference](#api-reference)
  - [Streaming API](#streaming-api)
  - [One-Shot Methods](#one-shot-methods)
  - [File Hashing](#file-hashing)
  - [Utility Functions](#utility-functions)
- [Usage Examples](#usage-examples)

---

## Project Structure

```
hazar.pas           Core algorithm — THazarEncryption key scheduler
hazarhash.pas       Hash algorithm implementation
hazarhashdemo.pas   Command-line tool
```

---

## Algorithm Design

HazarHash is a **stateful iterative hash** using `THazarEncryption` as its compression function. Its structure is loosely inspired by Merkle-Damgård but differs significantly: the state is fully re-keyed after every block, making the construction strongly non-linear.

### Initialization Vector

The cipher is never seeded from an all-zero state. A fixed non-trivial IV is applied at construction:

```
IV[I] = $5A   if I is even
IV[I] = $A5   if I is odd
IVLen = $5A
```

This alternating `$5A / $A5` pattern (`01011010 / 10100101`) ensures that the S-Box and M-Box generated during `THazarEncryption.Initialize` begin from a maximally non-degenerate state, eliminating the weak-key risk of an all-zero seed.

---

### Absorption — Compression Function

Data is fed to the hash in 256-byte blocks (matching the native block size of `THazarEncryption` in `hazar8` mode). For each block `M[0..255]`:

```
Step 1 — Generate keystream from current cipher state:
  K := Cipher.GenerateKey

Step 2 — Fold message block into new key material:
  NewKey[I] := K[I] xor M[I]   for I in 0..255

Step 3 — Re-initialize cipher with new key:
  KeyLength := low byte of cumulative message length mod 256
  Cipher    := THazarEncryption.Initialize(NewKey, KeyLength)
```

The previous cipher instance is freed and replaced. Every absorbed block permanently and irreversibly advances the state — the hash encodes the complete ordered history of all preceding blocks.

**Why XOR with the keystream rather than directly with the message?**
Feeding the raw message bytes into the key would create a linear relationship between input and state. XOR-ing with the keystream first means the message is mixed through the full non-linear S-Box/M-Box transformation of `THazarEncryption.GenerateKey` before it enters the new key. This breaks any direct algebraic relationship between message content and cipher state.

---

### Padding

After all message data has been absorbed, the partial trailing block is padded before the final absorption. The scheme encodes both a message terminator and the exact original length:

```
Block layout (256 bytes):
┌────────────────────────────────────────────────────────────────────────┐
│  bytes 0 .. (BufLen-1)  : last message bytes (already in buffer)       │
│  byte  BufLen           : $01  (terminator marker)                     │
│  bytes BufLen+1 .. 247  : $00  (zero fill)                             │
│  bytes 248 .. 255       : original message length in bytes,            │
│                           big-endian Int64                             │
└────────────────────────────────────────────────────────────────────────┘
```

**Edge case — no room for the length field:**
If fewer than 9 bytes remain in the buffer after the last data byte (positions 248–255 are already partially occupied), the current block is flushed with only the `$01` marker and zeros. A second all-zero block with the length in positions 248–255 is then absorbed. This prevents any ambiguity between messages that differ only in their final bytes.

---

### Finalization — Squeeze

After padding, two consecutive keystream blocks are generated from the post-absorption cipher state and XOR'd together to produce the 256-byte finalization state:

```
A := Cipher.GenerateKey
B := Cipher.GenerateKey
FinalState[I] := A[I] xor B[I]   for I in 0..255
```

The requested digest is taken from the front of `FinalState`:

```
128-bit  →  FinalState[0..15]    (16 bytes)
256-bit  →  FinalState[0..31]    (32 bytes)
512-bit  →  FinalState[0..63]    (64 bytes)
```

XOR-ing two consecutive blocks ensures that residual bias in either individual block is cancelled: a byte that is unexpectedly skewed in block A is likely independent in block B, and their XOR distributes more uniformly.

---

### Digest Sizes

| Type | Bytes | Hex chars | Bits |
|---|---|---|---|
| `THazarDigest128` | 16 | 32 | 128 |
| `THazarDigest256` | 32 | 64 | 256 |
| `THazarDigest512` | 64 | 128 | 512 |

All three digest sizes are derived from the same 256-byte finalization state — a larger digest simply takes more bytes from the front of that state. There is no additional computation cost for a larger digest.

---

## Security Properties

**Avalanche effect** — the XOR of message data into the cipher key, followed by a full re-initialization of both the S-Box and M-Box via `GenerateBox`, means a single-bit change in the message propagates into a completely different internal state within one block.

**Length separation** — the message length is encoded into the final padding block as a big-endian `Int64`. Two messages with different lengths but the same prefix cannot produce the same digest.

**Non-length-extension** — the squeeze step generates two fresh keystream blocks and XOR's them together. The finalization state is not the raw cipher state; an attacker cannot append data to a known hash without knowing the internal state after finalization.

**No weak IV** — the `$5A/$A5` IV ensures the cipher never initializes from a degenerate all-zero state, which could produce weak S-Boxes.

**Constant-time comparison** — `DigestEqual` never short-circuits on a mismatch. Every byte of both digests is always compared via XOR accumulation, preventing timing side-channel attacks on digest comparison.

---

## Building

```sh
fpc hazarhashdemo.pas
```

Or open `hazarhashdemo.pas` as the main program in **Lazarus** and build normally.

All three files must be in the same directory at compile time:

```
hazar.pas
hazarhash.pas
hazarhashdemo.pas
```

No external libraries or packages are required.

---

## Command-Line Tool

```
hazarhashdemo <command> <bits> [arguments]
```

`<bits>` must be `128`, `256`, or `512` for all commands.

---

### `string` — Hash a text string

```
hazarhashdemo string <bits> <text>
```

Hashes the literal text argument and prints the digest.

```
hazarhashdemo string 256 "hello world"
HazarHash-256 ("hello world")
a3f1c8e2...
```

---

### `file` — Hash a file

```
hazarhashdemo file <bits> <filepath>
```

Hashes the complete contents of a file and prints the digest.

```
hazarhashdemo file 256 document.pdf
HazarHash-256  document.pdf
e94f2b1a...
```

---

### `check` — Compare against a known digest

```
hazarhashdemo check <bits> <filepath> <expected_hex>
```

Hashes the file and compares it against `<expected_hex>`. Comparison is case-insensitive.

```
hazarhashdemo check 256 document.pdf e94f2b1a...
document.pdf ... OK

hazarhashdemo check 256 document.pdf wrongvalue
document.pdf ... MISMATCH
  Expected: wrongvalue
  Actual:   e94f2b1a...
```

Exits `0` on match, `3` on mismatch — useful in scripts and CI pipelines.

---

### `verify` — Batch verification from a hash file

```
hazarhashdemo verify <bits> <hashfile>
```

Reads a hash file and verifies every listed file. Output shows the result for each entry, then a summary line.

**Hash file format:**
```
# Lines starting with # are comments and are skipped.
# Blank lines are also skipped.
# Format: <hex_digest>  <filepath>

e94f2b1a...  document.pdf
a3f1c8e2...  photo.jpg
7d90cc3f...  archive.zip
```

**Example output:**
```
Verifying with HazarHash-256  |  source: checksums.txt
------------------------------------------------------------------------
  OK       document.pdf
  OK       photo.jpg
  MISSING  archive.zip
------------------------------------------------------------------------
Result: 2 OK,  1 FAILED,  0 skipped.
```

Per-entry status values:

| Status | Meaning |
|---|---|
| `OK` | File found, digest matches |
| `FAIL` | File found, digest does not match |
| `MISSING` | File not found on disk |
| `ERROR` | File found but could not be read |
| `SKIP` | Malformed line — skipped |

---

### Exit Codes

| Code | Meaning |
|---|---|
| 0 | Success / all files verified |
| 1 | Bad arguments or unknown command |
| 2 | File not found or I/O error |
| 3 | Hash mismatch (check / verify) |

---

### Examples

```sh
# Hash a string
hazarhashdemo string 128 "The quick brown fox"
hazarhashdemo string 512 "The quick brown fox"

# Hash files
hazarhashdemo file 256 backup.tar.gz
hazarhashdemo file 512 firmware.bin

# Check a file against a known digest
hazarhashdemo check 256 backup.tar.gz e94f2b1a...

# Generate a hash file (redirect output, strip the header line)
hazarhashdemo file 256 file1.bin | tail -1 > checksums.txt
hazarhashdemo file 256 file2.bin | tail -1 >> checksums.txt

# Manually create a hash file and verify
# checksums.txt:
#   e94f2b1a...  file1.bin
#   a3c90d5f...  file2.bin
hazarhashdemo verify 256 checksums.txt

# Use exit code in a script
hazarhashdemo check 256 payload.bin $EXPECTED_HASH
if [ $? -ne 0 ]; then echo "Integrity check failed!"; exit 1; fi
```

---

## API Reference

### Streaming API

```pascal
constructor THazarHash.Create;
```
Creates a new hash instance seeded with the built-in IV. Always call `Free` when done.

```pascal
procedure THazarHash.Update(const Data; DataLen: integer);
```
Feeds `DataLen` bytes of `Data` into the hash. May be called any number of times. Raises `EInvalidOperation` if called after `Digest128/256/512`.

```pascal
procedure THazarHash.UpdateStr(const S: string);
```
Convenience overload — feeds the raw bytes of a Pascal string.

```pascal
procedure THazarHash.Digest128(out Hash: THazarDigest128);
procedure THazarHash.Digest256(out Hash: THazarDigest256);
procedure THazarHash.Digest512(out Hash: THazarDigest512);
```
Finalizes the hash and writes the digest into `Hash`. After calling any of these, further `Update` calls raise an exception. Create a new instance to hash a different message.

---

### One-Shot Methods

```pascal
class procedure THazarHash.Hash128(const Data; DataLen: integer; out Hash: THazarDigest128);
class procedure THazarHash.Hash256(const Data; DataLen: integer; out Hash: THazarDigest256);
class procedure THazarHash.Hash512(const Data; DataLen: integer; out Hash: THazarDigest512);
```

```pascal
class procedure THazarHash.HashStr128(const S: string; out Hash: THazarDigest128);
class procedure THazarHash.HashStr256(const S: string; out Hash: THazarDigest256);
class procedure THazarHash.HashStr512(const S: string; out Hash: THazarDigest512);
```

Each method creates an instance internally, absorbs all data, finalizes, and frees — one call, no manual lifecycle management.

---

### File Hashing

```pascal
class function THazarHash.FileHash128(const FileName: string; out Hash: THazarDigest128): boolean;
class function THazarHash.FileHash256(const FileName: string; out Hash: THazarDigest256): boolean;
class function THazarHash.FileHash512(const FileName: string; out Hash: THazarDigest512): boolean;
```

Hashes an entire file in 256-byte reads. Returns `True` on success, `False` if the file does not exist or cannot be read.

---

### Utility Functions

```pascal
function DigestToHex(const Digest; DigestSize: integer): string;
```
Converts any digest to a lowercase hex string. Works with all three digest types:
```pascal
DigestToHex(D256, SizeOf(D256))   // → 64-character hex string
```

```pascal
function DigestEqual(const A, B; DigestSize: integer): boolean;
```
Compares two digests in **constant time** — the comparison always touches every byte regardless of where (or whether) a mismatch occurs. Use this instead of direct array comparison whenever digests come from untrusted input to prevent timing side-channel attacks.

---

## Usage Examples

**Hash a buffer and print hex:**
```pascal
var
  H  : THazarHash;
  D  : THazarDigest256;
begin
  H := THazarHash.Create;
  try
    H.Update(Buffer, BufferLen);
    H.Digest256(D);
    WriteLn(DigestToHex(D, SizeOf(D)));
  finally
    H.Free;
  end;
end;
```

**Incremental hashing:**
```pascal
H := THazarHash.Create;
H.Update(Header, HeaderLen);
H.Update(Payload, PayloadLen);
H.Update(Footer, FooterLen);
H.Digest512(D);
H.Free;
```

**One-shot string hash:**
```pascal
THazarHash.HashStr256('hello world', D);
WriteLn(DigestToHex(D, SizeOf(D)));
```

**File integrity check:**
```pascal
if THazarHash.FileHash256('firmware.bin', Actual) then
begin
  if DigestEqual(Actual, Expected, SizeOf(Actual)) then
    WriteLn('OK')
  else
    WriteLn('CORRUPTED');
end;
```

---

## License

This project is released as open source. See `LICENSE` for details.
