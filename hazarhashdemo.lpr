program hazarhashdemo;

{ =============================================================================
  HazarHashDemo — Command-line tool for hazarhash.pas
  Usage:
    hazarhashdemo string <bits> <text>
    hazarhashdemo file   <bits> <filepath>
    hazarhashdemo check  <bits> <filepath> <expected_hex>
    hazarhashdemo verify <bits> <hashfile>

  Digest sizes:
    128  →  16 bytes / 32 hex chars
    256  →  32 bytes / 64 hex chars
    512  →  64 bytes / 128 hex chars
  ============================================================================= }

{$mode objfpc}{$H+}
{$APPTYPE CONSOLE}

uses
  SysUtils, Classes,
  hazar       in 'hazar.pas',
  hazarhash   in 'hazarhash.pas';

{ --------------------------------------------------------------------------- }
{ Helpers                                                                     }
{ --------------------------------------------------------------------------- }

procedure PrintUsage;
begin
  WriteLn('HazarHash -- Data Integrity Tool');
  WriteLn('--------------------------------');
  WriteLn('Usage:');
  WriteLn;
  WriteLn('  hazarhashdemo string <bits> <text>');
  WriteLn('      Hash a text string directly.');
  WriteLn;
  WriteLn('  hazarhashdemo file <bits> <filepath>');
  WriteLn('      Hash a file and print the digest.');
  WriteLn;
  WriteLn('  hazarhashdemo check <bits> <filepath> <expected_hex>');
  WriteLn('      Hash a file and compare it to an expected digest.');
  WriteLn('      Exits 0 if match, 3 if mismatch.');
  WriteLn;
  WriteLn('  hazarhashdemo verify <bits> <hashfile>');
  WriteLn('      Verify multiple files listed in a hash file.');
  WriteLn('      Hash file format (one entry per line):');
  WriteLn('        <hex_digest>  <filepath>');
  WriteLn('      Lines starting with # are treated as comments.');
  WriteLn;
  WriteLn('  <bits> must be 128, 256, or 512.');
  WriteLn;
  WriteLn('Exit codes:');
  WriteLn('  0  Success / all files verified');
  WriteLn('  1  Bad arguments');
  WriteLn('  2  File not found or I/O error');
  WriteLn('  3  Hash mismatch (check / verify)');
end;

{ Hash a file for the given bit width.
  Returns the hex digest string on success, empty string on failure. }
function HashFile(const FilePath: string; Bits: integer): string;
var
  D128: THazarDigest128;
  D256: THazarDigest256;
  D512: THazarDigest512;
begin
  Result := '';
  case Bits of
    128:
      if THazarHash.FileHash128(FilePath, D128) then
        Result := DigestToHex(D128, SizeOf(D128));
    256:
      if THazarHash.FileHash256(FilePath, D256) then
        Result := DigestToHex(D256, SizeOf(D256));
    512:
      if THazarHash.FileHash512(FilePath, D512) then
        Result := DigestToHex(D512, SizeOf(D512));
  end;
end;

{ Hash a string for the given bit width. }
function HashString(const S: string; Bits: integer): string;
var
  D128: THazarDigest128;
  D256: THazarDigest256;
  D512: THazarDigest512;
begin
  Result := '';
  case Bits of
    128: begin THazarHash.HashStr128(S, D128); Result := DigestToHex(D128, SizeOf(D128)); end;
    256: begin THazarHash.HashStr256(S, D256); Result := DigestToHex(D256, SizeOf(D256)); end;
    512: begin THazarHash.HashStr512(S, D512); Result := DigestToHex(D512, SizeOf(D512)); end;
  end;
end;

{ Parse <bits> argument. Returns -1 on invalid input. }
function ParseBits(const S: string): integer;
begin
  Result := StrToIntDef(S, -1);
  if (Result <> 128) and (Result <> 256) and (Result <> 512) then
    Result := -1;
end;

{ --------------------------------------------------------------------------- }
{ Commands                                                                    }
{ --------------------------------------------------------------------------- }

{ hazarhashdemo string <bits> <text> }
procedure CmdString;
var
  Bits  : integer;
  Text  : string;
  Digest: string;
begin
  if ParamCount <> 3 then
  begin
    WriteLn('ERROR: string requires exactly 2 arguments.');
    WriteLn;
    PrintUsage;
    Halt(1);
  end;
  Bits := ParseBits(ParamStr(2));
  if Bits = -1 then
  begin
    WriteLn('ERROR: <bits> must be 128, 256, or 512.');
    Halt(1);
  end;
  Text   := ParamStr(3);
  Digest := HashString(Text, Bits);
  WriteLn(Format('HazarHash-%d ("%s")', [Bits, Text]));
  WriteLn(Digest);
end;

{ hazarhashdemo file <bits> <filepath> }
procedure CmdFile;
var
  Bits    : integer;
  FilePath: string;
  Digest  : string;
begin
  if ParamCount <> 3 then
  begin
    WriteLn('ERROR: file requires exactly 2 arguments.');
    WriteLn;
    PrintUsage;
    Halt(1);
  end;
  Bits := ParseBits(ParamStr(2));
  if Bits = -1 then
  begin
    WriteLn('ERROR: <bits> must be 128, 256, or 512.');
    Halt(1);
  end;
  FilePath := ParamStr(3);
  if not FileExists(FilePath) then
  begin
    WriteLn('ERROR: File not found: ', FilePath);
    Halt(2);
  end;
  Digest := HashFile(FilePath, Bits);
  if Digest = '' then
  begin
    WriteLn('ERROR: Failed to hash file: ', FilePath);
    Halt(2);
  end;
  WriteLn(Format('HazarHash-%d  %s', [Bits, FilePath]));
  WriteLn(Digest);
end;

{ hazarhashdemo check <bits> <filepath> <expected_hex> }
procedure CmdCheck;
var
  Bits    : integer;
  FilePath: string;
  Expected: string;
  Actual  : string;
begin
  if ParamCount <> 4 then
  begin
    WriteLn('ERROR: check requires exactly 3 arguments.');
    WriteLn;
    PrintUsage;
    Halt(1);
  end;
  Bits := ParseBits(ParamStr(2));
  if Bits = -1 then
  begin
    WriteLn('ERROR: <bits> must be 128, 256, or 512.');
    Halt(1);
  end;
  FilePath := ParamStr(3);
  Expected := LowerCase(Trim(ParamStr(4)));
  if not FileExists(FilePath) then
  begin
    WriteLn('ERROR: File not found: ', FilePath);
    Halt(2);
  end;
  Actual := HashFile(FilePath, Bits);
  if Actual = '' then
  begin
    WriteLn('ERROR: Failed to hash file: ', FilePath);
    Halt(2);
  end;
  Write(FilePath, ' ... ');
  if Actual = Expected then
    WriteLn('OK')
  else
  begin
    WriteLn('MISMATCH');
    WriteLn('  Expected: ', Expected);
    WriteLn('  Actual:   ', Actual);
    Halt(3);
  end;
end;

{ hazarhashdemo verify <bits> <hashfile>
  Hash file format (one line per file):
    <hex>  <filepath>
  Lines starting with # are comments and are skipped.
  Blank lines are skipped. }
procedure CmdVerify;
var
  Bits      : integer;
  Hash_File  : string;
  SL        : TStringList;
  Line      : string;
  Parts     : TStringArray;
  Expected  : string;
  FilePath  : string;
  Actual    : string;
  TotalOK   : integer;
  TotalFail : integer;
  TotalSkip : integer;
  I         : integer;
  HasError  : boolean;
begin
  if ParamCount <> 3 then
  begin
    WriteLn('ERROR: verify requires exactly 2 arguments.');
    WriteLn;
    PrintUsage;
    Halt(1);
  end;
  Bits := ParseBits(ParamStr(2));
  if Bits = -1 then
  begin
    WriteLn('ERROR: <bits> must be 128, 256, or 512.');
    Halt(1);
  end;
  Hash_File := ParamStr(3);
  if not FileExists(Hash_File) then
  begin
    WriteLn('ERROR: Hash file not found: ', Hash_File);
    Halt(2);
  end;

  SL := TStringList.Create;
  try
    SL.LoadFromFile(Hash_File);
  except
    SL.Free;
    WriteLn('ERROR: Could not read hash file: ', Hash_File);
    Halt(2);
  end;

  TotalOK   := 0;
  TotalFail := 0;
  TotalSkip := 0;
  HasError  := False;

  WriteLn(Format('Verifying with HazarHash-%d  |  source: %s', [Bits, Hash_File]));
  WriteLn(StringOfChar('-', 72));

  try
    for I := 0 to SL.Count - 1 do
    begin
      Line := Trim(SL[I]);

      { Skip blank lines and comments }
      if (Line = '') or (Line[1] = '#') then
      begin
        Inc(TotalSkip);
        Continue;
      end;

      { Split on whitespace — expected format: <hex>  <path> }
      Parts := Line.Split([' ', #9], TStringSplitOptions.ExcludeEmpty);
      if Length(Parts) < 2 then
      begin
        WriteLn('  SKIP  (malformed line ', I + 1, '): ', Line);
        Inc(TotalSkip);
        Continue;
      end;

      Expected := LowerCase(Trim(Parts[0]));
      FilePath := Trim(Parts[1]);

      if not FileExists(FilePath) then
      begin
        WriteLn(Format('  MISSING  %s', [FilePath]));
        Inc(TotalFail);
        HasError := True;
        Continue;
      end;

      Actual := HashFile(FilePath, Bits);
      if Actual = '' then
      begin
        WriteLn(Format('  ERROR    %s  (could not hash)', [FilePath]));
        Inc(TotalFail);
        HasError := True;
        Continue;
      end;

      if Actual = Expected then
      begin
        WriteLn(Format('  OK       %s', [FilePath]));
        Inc(TotalOK);
      end else
      begin
        WriteLn(Format('  FAIL     %s', [FilePath]));
        WriteLn(Format('           expected: %s', [Expected]));
        WriteLn(Format('           actual:   %s', [Actual]));
        Inc(TotalFail);
        HasError := True;
      end;
    end;
  finally
    SL.Free;
  end;

  WriteLn(StringOfChar('-', 72));
  WriteLn(Format('Result: %d OK,  %d FAILED,  %d skipped.',
    [TotalOK, TotalFail, TotalSkip]));

  if HasError then Halt(3);
end;

{ --------------------------------------------------------------------------- }
{ Entry point                                                                 }
{ --------------------------------------------------------------------------- }

var
  Cmd: string;

begin
  if ParamCount < 1 then
  begin
    PrintUsage;
    Halt(1);
  end;

  Cmd := LowerCase(ParamStr(1));

  if      Cmd = 'string' then CmdString
  else if Cmd = 'file'   then CmdFile
  else if Cmd = 'check'  then CmdCheck
  else if Cmd = 'verify' then CmdVerify
  else
  begin
    WriteLn('ERROR: Unknown command "', ParamStr(1), '".');
    WriteLn;
    PrintUsage;
    Halt(1);
  end;
end.
