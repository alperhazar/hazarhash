unit hazarhash;

{
  HazarHash — Data Integrity / Hash Algorithm
  ============================================
  Built entirely on top of THazarEncryption from hazar.pas.

  ── Construction ────────────────────────────────────────────────────────────
  HazarHash uses an iterative compression construction similar in spirit to
  Merkle-Damgård, but the compression function is THazarEncryption itself.

  For each 256-byte message block M:
    1. Generate a keystream block K from the current cipher state.
    2. XOR K with M to produce new key material:  NewKey[I] = K[I] xor M[I]
    3. Re-initialize the cipher with NewKey and a KeyLength derived from the
       running message length. The previous cipher state is discarded.

  This means every absorbed block permanently mutates the cipher state, and
  the state after block N encodes the complete history of blocks 0..N.

  ── Padding ─────────────────────────────────────────────────────────────────
  After all data is absorbed, the trailing partial block is padded:
    - Append marker byte $01 immediately after the last data byte.
    - Zero-fill to byte 247 of the block (248 data bytes total).
    - Write the original message length in bytes as a big-endian Int64 into
      the final 8 bytes of the block (bytes 248..255).
    - If fewer than 9 bytes remain in the current block after the last data
      byte (no room for $01 + 8-byte length), the current block is flushed
      with only the $01 marker + zeros, and a second all-zero block with the
      length in bytes 248..255 is absorbed.

  ── Finalization (squeeze) ───────────────────────────────────────────────────
  Two consecutive keystream blocks A and B are generated from the post-
  padding cipher state. They are XOR'd together:
    FinalState[I] = A[I] xor B[I]

  This produces a 256-byte finalization state. The requested digest is taken
  from the front of that state:
    128-bit  →  FinalState[0..15]
    256-bit  →  FinalState[0..31]
    512-bit  →  FinalState[0..63]

  ── Initialization Vector ────────────────────────────────────────────────────
  The cipher is seeded with a fixed non-trivial IV so that hashing the empty
  message does not start from an all-zero weak state:
    IV[I]  = $5A if I is even, $A5 if I is odd
    IVLen  = $5A

  ── One-shot API ─────────────────────────────────────────────────────────────
  Class methods Hash128/Hash256/Hash512 handle Create/Update/Digest/Free.
  FileHash128/FileHash256/FileHash512 hash a file from disk directly.

  ── Usage example ────────────────────────────────────────────────────────────
    var
      H   : THazarHash;
      D   : THazarDigest256;
      Hex : string;
    begin
      H := THazarHash.Create;
      try
        H.Update(Buffer, Length(Buffer));
        H.Digest256(D);
        Hex := DigestToHex(D, SizeOf(D));
        WriteLn(Hex);
      finally
        H.Free;
      end;
    end;
}

{$mode objfpc}{$H+}

interface

uses
  hazar, SysUtils, Classes;

const
  HAZARHASH_BLOCK = 256;   { Absorption block size = THazarData element count }

type
  THazarDigest128 = array [0 .. 15] of byte;
  THazarDigest256 = array [0 .. 31] of byte;
  THazarDigest512 = array [0 .. 63] of byte;

  THazarHash = class
  private
    FCipher    : THazarEncryption;
    FMsgLen    : Int64;
    FBuf       : THazarData;   { partial block accumulator, always 256 bytes }
    FBufLen    : integer;      { bytes currently filled in FBuf (0..255)      }
    FFinalized : boolean;
    FState     : THazarData;   { 256-byte squeeze output, set on finalization  }

    procedure AbsorbBlock(const Block: THazarData);
    procedure Finalize;

  public
    constructor Create;
    destructor  Destroy; override;

    { Feed arbitrary-length data into the hash state.
      May be called any number of times before Digest.
      Raises EInvalidOperation if called after a Digest call. }
    procedure Update(const Data; DataLen: integer);

    { Convenience overload for strings. }
    procedure UpdateStr(const S: string);

    { Finalize and return the digest. Calls to Update after Digest raise an
      exception. Create a new instance to hash a different message. }
    procedure Digest128(out Hash: THazarDigest128);
    procedure Digest256(out Hash: THazarDigest256);
    procedure Digest512(out Hash: THazarDigest512);

    { ── One-shot class methods ─────────────────────────────────────────── }

    class procedure Hash128(const Data; DataLen: integer; out Hash: THazarDigest128);
    class procedure Hash256(const Data; DataLen: integer; out Hash: THazarDigest256);
    class procedure Hash512(const Data; DataLen: integer; out Hash: THazarDigest512);

    class procedure HashStr128(const S: string; out Hash: THazarDigest128);
    class procedure HashStr256(const S: string; out Hash: THazarDigest256);
    class procedure HashStr512(const S: string; out Hash: THazarDigest512);

    class function FileHash128(const FileName: string; out Hash: THazarDigest128): boolean;
    class function FileHash256(const FileName: string; out Hash: THazarDigest256): boolean;
    class function FileHash512(const FileName: string; out Hash: THazarDigest512): boolean;
  end;

{ Convert any digest to a lowercase hex string. }
function DigestToHex(const Digest; DigestSize: integer): string;

{ Compare two digests of the same size in constant time.
  Returns True if every byte is equal. }
function DigestEqual(const A, B; DigestSize: integer): boolean;

implementation

{ ── Internal IV ─────────────────────────────────────────────────────────── }

procedure BuildIV(out Key: THazarData; out KLen: THazarInteger);
var
  I: integer;
begin
  for I := S to E do
    if (I and 1) = 0 then Key[I] := $5A
    else                   Key[I] := $A5;
  KLen := $5A;
end;

{ ── Encode big-endian Int64 into 8 bytes ─────────────────────────────────── }

procedure WriteInt64BE(var Buf: THazarData; Offset: integer; V: Int64);
var
  I: integer;
begin
  for I := 7 downto 0 do
  begin
    Buf[Offset + I] := byte(V and $FF);
    V := V shr 8;
  end;
end;

{ ── THazarHash ───────────────────────────────────────────────────────────── }

constructor THazarHash.Create;
var
  IV  : THazarData;
  KLen: THazarInteger;
begin
  inherited Create;
  BuildIV(IV, KLen);
  FCipher    := THazarEncryption.Initialize(IV, KLen);
  FMsgLen    := 0;
  FBufLen    := 0;
  FFinalized := False;
  FillChar(FBuf,   SizeOf(FBuf),   0);
  FillChar(FState, SizeOf(FState), 0);
end;

destructor THazarHash.Destroy;
begin
  FCipher.Free;
  { Zero sensitive state before releasing memory }
  FillChar(FBuf,   SizeOf(FBuf),   0);
  FillChar(FState, SizeOf(FState), 0);
  inherited Destroy;
end;

{ ── AbsorbBlock ──────────────────────────────────────────────────────────── }
{ Core compression step.
  KeyStream = GenerateKey from current cipher state.
  NewKey[I] = KeyStream[I] xor Block[I]  for all I.
  Re-initialize cipher with NewKey; KeyLength = low byte of message length. }

procedure THazarHash.AbsorbBlock(const Block: THazarData);
var
  KeyStream : THazarData;
  NewKey    : THazarData;
  NewCipher : THazarEncryption;
  KLen      : THazarInteger;
  I         : integer;
begin
  KeyStream := FCipher.GenerateKey;
  for I := S to E do
    NewKey[I] := KeyStream[I] xor Block[I];
  KLen      := THazarInteger(FMsgLen mod N);
  NewCipher := THazarEncryption.Initialize(NewKey, KLen);
  FreeAndNil(FCipher);
  FCipher := NewCipher;
end;

{ ── Update ───────────────────────────────────────────────────────────────── }

procedure THazarHash.Update(const Data; DataLen: integer);
var
  Src  : PByte;
  Take : integer;
begin
  if FFinalized then
    raise EInvalidOperation.Create('THazarHash: Update called after Digest.');
  if DataLen <= 0 then Exit;

  Src := PByte(@Data);
  Inc(FMsgLen, DataLen);

  while DataLen > 0 do
  begin
    { Fill the partial buffer }
    Take := HAZARHASH_BLOCK - FBufLen;
    if Take > DataLen then Take := DataLen;
    Move(Src^, FBuf[FBufLen], Take);
    Inc(FBufLen, Take);
    Inc(Src,    Take);
    Dec(DataLen, Take);

    { Absorb when we have a full block }
    if FBufLen = HAZARHASH_BLOCK then
    begin
      AbsorbBlock(FBuf);
      FillChar(FBuf, SizeOf(FBuf), 0);
      FBufLen := 0;
    end;
  end;
end;

procedure THazarHash.UpdateStr(const S: string);
begin
  if Length(S) > 0 then
    Update(S[1], Length(S));
end;

{ ── Finalize ─────────────────────────────────────────────────────────────── }

procedure THazarHash.Finalize;
var
  A, B: THazarData;
  I   : integer;
begin
  if FFinalized then Exit;
  FFinalized := True;

  { Append $01 marker }
  FBuf[FBufLen] := $01;
  Inc(FBufLen);

  { Zero-fill up to byte 247 }
  while FBufLen < 248 do
  begin
    FBuf[FBufLen] := $00;
    Inc(FBufLen);
  end;

  { If there are already data bytes in positions 248..255, the current block
    has no room for the 8-byte length — flush it and start a new padding block. }
  if FBufLen > 248 then
  begin
    AbsorbBlock(FBuf);
    FillChar(FBuf, SizeOf(FBuf), 0);
    FBufLen := 248;
  end;

  { Write original message length (bytes) as big-endian Int64 at bytes 248..255 }
  WriteInt64BE(FBuf, 248, FMsgLen);
  AbsorbBlock(FBuf);
  FillChar(FBuf, SizeOf(FBuf), 0);
  FBufLen := 0;

  { Squeeze: generate two blocks and XOR them together }
  A := FCipher.GenerateKey;
  B := FCipher.GenerateKey;
  for I := S to E do
    FState[I] := A[I] xor B[I];
end;

{ ── Digest ───────────────────────────────────────────────────────────────── }

procedure THazarHash.Digest128(out Hash: THazarDigest128);
begin
  Finalize;
  Move(FState[0], Hash[0], SizeOf(Hash));
end;

procedure THazarHash.Digest256(out Hash: THazarDigest256);
begin
  Finalize;
  Move(FState[0], Hash[0], SizeOf(Hash));
end;

procedure THazarHash.Digest512(out Hash: THazarDigest512);
begin
  Finalize;
  Move(FState[0], Hash[0], SizeOf(Hash));
end;

{ ── One-shot class methods ─────────────────────────────────────────────── }

class procedure THazarHash.Hash128(const Data; DataLen: integer; out Hash: THazarDigest128);
var H: THazarHash;
begin
  H := THazarHash.Create;
  try H.Update(Data, DataLen); H.Digest128(Hash); finally H.Free; end;
end;

class procedure THazarHash.Hash256(const Data; DataLen: integer; out Hash: THazarDigest256);
var H: THazarHash;
begin
  H := THazarHash.Create;
  try H.Update(Data, DataLen); H.Digest256(Hash); finally H.Free; end;
end;

class procedure THazarHash.Hash512(const Data; DataLen: integer; out Hash: THazarDigest512);
var H: THazarHash;
begin
  H := THazarHash.Create;
  try H.Update(Data, DataLen); H.Digest512(Hash); finally H.Free; end;
end;

class procedure THazarHash.HashStr128(const S: string; out Hash: THazarDigest128);
var H: THazarHash;
begin
  H := THazarHash.Create;
  try H.UpdateStr(S); H.Digest128(Hash); finally H.Free; end;
end;

class procedure THazarHash.HashStr256(const S: string; out Hash: THazarDigest256);
var H: THazarHash;
begin
  H := THazarHash.Create;
  try H.UpdateStr(S); H.Digest256(Hash); finally H.Free; end;
end;

class procedure THazarHash.HashStr512(const S: string; out Hash: THazarDigest512);
var H: THazarHash;
begin
  H := THazarHash.Create;
  try H.UpdateStr(S); H.Digest512(Hash); finally H.Free; end;
end;

class function THazarHash.FileHash128(const FileName: string; out Hash: THazarDigest128): boolean;
var
  H      : THazarHash;
  Stream : TFileStream;
  Buf    : array [0 .. HAZARHASH_BLOCK - 1] of byte;
  Bytes  : integer;
begin
  Result := False;
  if not FileExists(FileName) then Exit;
  H := THazarHash.Create;
  try
    Stream := TFileStream.Create(FileName, fmOpenRead or fmShareDenyWrite);
    try
      repeat
        Bytes := Stream.Read(Buf, SizeOf(Buf));
        if Bytes > 0 then H.Update(Buf, Bytes);
      until Bytes < SizeOf(Buf);
    finally
      Stream.Free;
    end;
    H.Digest128(Hash);
    Result := True;
  finally
    H.Free;
  end;
end;

class function THazarHash.FileHash256(const FileName: string; out Hash: THazarDigest256): boolean;
var
  H      : THazarHash;
  Stream : TFileStream;
  Buf    : array [0 .. HAZARHASH_BLOCK - 1] of byte;
  Bytes  : integer;
begin
  Result := False;
  if not FileExists(FileName) then Exit;
  H := THazarHash.Create;
  try
    Stream := TFileStream.Create(FileName, fmOpenRead or fmShareDenyWrite);
    try
      repeat
        Bytes := Stream.Read(Buf, SizeOf(Buf));
        if Bytes > 0 then H.Update(Buf, Bytes);
      until Bytes < SizeOf(Buf);
    finally
      Stream.Free;
    end;
    H.Digest256(Hash);
    Result := True;
  finally
    H.Free;
  end;
end;

class function THazarHash.FileHash512(const FileName: string; out Hash: THazarDigest512): boolean;
var
  H      : THazarHash;
  Stream : TFileStream;
  Buf    : array [0 .. HAZARHASH_BLOCK - 1] of byte;
  Bytes  : integer;
begin
  Result := False;
  if not FileExists(FileName) then Exit;
  H := THazarHash.Create;
  try
    Stream := TFileStream.Create(FileName, fmOpenRead or fmShareDenyWrite);
    try
      repeat
        Bytes := Stream.Read(Buf, SizeOf(Buf));
        if Bytes > 0 then H.Update(Buf, Bytes);
      until Bytes < SizeOf(Buf);
    finally
      Stream.Free;
    end;
    H.Digest512(Hash);
    Result := True;
  finally
    H.Free;
  end;
end;

{ ── Utility ─────────────────────────────────────────────────────────────── }

function DigestToHex(const Digest; DigestSize: integer): string;
const
  HexChars: string = '0123456789abcdef';
var
  B  : PByte;
  I  : integer;
begin
  SetLength(Result, DigestSize * 2);
  B := PByte(@Digest);
  for I := 0 to DigestSize - 1 do
  begin
    Result[I * 2 + 1] := HexChars[(B[I] shr 4) + 1];
    Result[I * 2 + 2] := HexChars[(B[I] and $0F) + 1];
  end;
end;

function DigestEqual(const A, B; DigestSize: integer): boolean;
var
  PA, PB: PByte;
  Diff  : byte;
  I     : integer;
begin
  { Constant-time comparison — does not short-circuit on first mismatch }
  PA   := PByte(@A);
  PB   := PByte(@B);
  Diff := 0;
  for I := 0 to DigestSize - 1 do
    Diff := Diff or (PA[I] xor PB[I]);
  Result := (Diff = 0);
end;

end.
