{ *********************************************************************** }
{ Copyright (c) 2010-2011 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.Hash.XUM32;

interface

uses System.SysUtils, Rf.Hash, Rf.Types;

type

{ THashXUM32 }

  THashXUM32 = class(THash)
  private
    FLength: DWORD;
    FCRC32: DWORD;
    FELF32: DWORD;
    FState: DWORD;
  private class var
    FTable: array[Byte] of DWORD;
    FTableInitialized: Boolean;
    class procedure CRC32TableInit;
  protected
    procedure Initialize; override;
    procedure Update(const Buffer: Pointer; const Size: Cardinal); override;
    procedure Finalize; override;
  public
    class function HashType: THashType; override;
    function HashSize: Cardinal; override;
  end;

implementation

{ THashXUM32 }

class function THashXUM32.HashType: THashType;
begin
  Result := THashType.Checksum;
end;

function THashXUM32.HashSize: Cardinal;
begin
  Result := 4;
end;

procedure THashXUM32.Initialize;
begin
  FLength := 0;
  FCRC32 := $FFFFFFFF;
  FELF32 := 0;
  CRC32TableInit;
end;

procedure THashXUM32.Update(const Buffer: Pointer; const Size: Cardinal);
var
  i: Integer;
  CRC32, ELF32, tst: DWORD;
  pb: PByte;
begin
  CRC32 := FCRC32;
  ELF32 := FELF32;
  pb := Buffer;
  for i := 0 to Size - 1 do
  begin
    // CRC:
    CRC32 := (CRC32 shr 8) xor FTable[(CRC32 xor pb^) and $FF];
    // ELF:
    ELF32 := (ELF32 shl 4) + pb^;
    tst := ELF32 and $F0000000;
    //if tst <> 0 then
      ELF32 := ELF32 xor RotateRight(tst, 24);
    ELF32 := ELF32 and not tst;

    Inc(pb);
  end;
  FCRC32 := CRC32;
  FELF32 := ELF32;
  Inc(FLength, Size);
end;

procedure THashXUM32.Finalize;
begin
  FState := (FLength shl 16) + (FLength shr 16);
  FState := FState xor not FCRC32;
  FState := FState xor (FELF32 mod 997);

  with LongRec(FState) do
  begin
    FValue[0] := Bytes[3];
    FValue[1] := Bytes[2];
    FValue[2] := Bytes[1];
    FValue[3] := Bytes[0];
  end;
end;

class procedure THashXUM32.CRC32TableInit;
var
  c: DWORD;
  i, j: Byte;
begin
  if not FTableInitialized then
  begin
    for i := 0 to 255 do
    begin
      c := i;
      for j := 0 to 7 do
        if Odd(c) then
          c := (c shr 1) xor $EDB88320
        else
          c := (c shr 1);
      FTable[i] := c;
    end;
    FTableInitialized := True;
  end;
end;

end.
