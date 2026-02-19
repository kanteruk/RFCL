{ *********************************************************************** }
{ Copyright (c) 2010-2011 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.Hash.MD4;

interface

uses Rf.Types, Rf.SysUtils, Rf.Hash;

type

  /// <summary>
  /// Message-Digest 4 (MD4)
  /// </summary>
  THashMD4 = class(TBlockHash)
  private
    FState: array[0..3] of Cardinal;
    FLength: UInt64;
  protected
    procedure Initialize; override;
    procedure UpdateBlock(const Block: Pointer); override;
    function GetPadBuffer: TBytes; override;
    procedure Finalize; override;
  public
    class function HashType: THashType; override;
    function HashSize: Cardinal; override;
    function BlockSize: Cardinal; override;
  end;

implementation

{ THashMD4 }

class function THashMD4.HashType: THashType;
begin
  Result := THashType.Cryptographic;
end;

function THashMD4.HashSize: Cardinal;
begin
  Result := 16;
end;

function THashMD4.BlockSize: Cardinal;
begin
  Result := 64;
end;

procedure THashMD4.Initialize;
begin
  inherited;
  FState[0] := $67452301;
  FState[1] := $EFCDAB89;
  FState[2] := $98BADCFE;
  FState[3] := $10325476;
  FLength := 0;
end;

procedure THashMD4.UpdateBlock(const Block: Pointer);
type
  TArray16UINT = array[0..15] of Cardinal;
const
  S11 = 03;
  S12 = 07;
  S13 = 11;
  S14 = 19;
  S21 = 03;
  S22 = 05;
  S23 = 09;
  S24 = 13;
  S31 = 03;
  S32 = 09;
  S33 = 11;
  S34 = 15;

  procedure StageF(var a: Cardinal; const b, c, d, x: Cardinal; const s: Byte); inline;
  begin
    a := RotateLeft(a + ((b and c) or ((not b) and d)) + x, s);
  end;

  procedure StageG(var a: Cardinal; const b, c, d, x: Cardinal; const s: Byte); inline;
  begin
    a := RotateLeft(a + ((b and c) or (b and d) or (c and d)) + x + $5A827999, s);
  end;

  procedure StageH(var a: Cardinal; const b, c, d, x: Cardinal; const s: Byte); inline;
  begin
    a := RotateLeft(a + (b xor c xor d) + x + $6ED9EBA1, s);
  end;

var
  A, B, C, D: Cardinal;
begin
  Inc(FLength, 64);

  A := FState[0];
  B := FState[1];
  C := FState[2];
  D := FState[3];

  { Stage 1 }
  StageF(a, b, c, d, TArray16UINT(Block^)[00], S11);
  StageF(d, a, b, c, TArray16UINT(Block^)[01], S12);
  StageF(c, d, a, b, TArray16UINT(Block^)[02], S13);
  StageF(b, c, d, a, TArray16UINT(Block^)[03], S14);
  StageF(a, b, c, d, TArray16UINT(Block^)[04], S11);
  StageF(d, a, b, c, TArray16UINT(Block^)[05], S12);
  StageF(c, d, a, b, TArray16UINT(Block^)[06], S13);
  StageF(b, c, d, a, TArray16UINT(Block^)[07], S14);
  StageF(a, b, c, d, TArray16UINT(Block^)[08], S11);
  StageF(d, a, b, c, TArray16UINT(Block^)[09], S12);
  StageF(c, d, a, b, TArray16UINT(Block^)[10], S13);
  StageF(b, c, d, a, TArray16UINT(Block^)[11], S14);
  StageF(a, b, c, d, TArray16UINT(Block^)[12], S11);
  StageF(d, a, b, c, TArray16UINT(Block^)[13], S12);
  StageF(c, d, a, b, TArray16UINT(Block^)[14], S13);
  StageF(b, c, d, a, TArray16UINT(Block^)[15], S14);

  { Stage 2 }
  StageG(a, b, c, d, TArray16UINT(Block^)[00], S21);
  StageG(d, a, b, c, TArray16UINT(Block^)[04], S22);
  StageG(c, d, a, b, TArray16UINT(Block^)[08], S23);
  StageG(b, c, d, a, TArray16UINT(Block^)[12], S24);
  StageG(a, b, c, d, TArray16UINT(Block^)[01], S21);
  StageG(d, a, b, c, TArray16UINT(Block^)[05], S22);
  StageG(c, d, a, b, TArray16UINT(Block^)[09], S23);
  StageG(b, c, d, a, TArray16UINT(Block^)[13], S24);
  StageG(a, b, c, d, TArray16UINT(Block^)[02], S21);
  StageG(d, a, b, c, TArray16UINT(Block^)[06], S22);
  StageG(c, d, a, b, TArray16UINT(Block^)[10], S23);
  StageG(b, c, d, a, TArray16UINT(Block^)[14], S24);
  StageG(a, b, c, d, TArray16UINT(Block^)[03], S21);
  StageG(d, a, b, c, TArray16UINT(Block^)[07], S22);
  StageG(c, d, a, b, TArray16UINT(Block^)[11], S23);
  StageG(b, c, d, a, TArray16UINT(Block^)[15], S24);

  { Stage 3 }
  StageH(a, b, c, d, TArray16UINT(Block^)[00], S31);
  StageH(d, a, b, c, TArray16UINT(Block^)[08], S32);
  StageH(c, d, a, b, TArray16UINT(Block^)[04], S33);
  StageH(b, c, d, a, TArray16UINT(Block^)[12], S34);
  StageH(a, b, c, d, TArray16UINT(Block^)[02], S31);
  StageH(d, a, b, c, TArray16UINT(Block^)[10], S32);
  StageH(c, d, a, b, TArray16UINT(Block^)[06], S33);
  StageH(b, c, d, a, TArray16UINT(Block^)[14], S34);
  StageH(a, b, c, d, TArray16UINT(Block^)[01], S31);
  StageH(d, a, b, c, TArray16UINT(Block^)[09], S32);
  StageH(c, d, a, b, TArray16UINT(Block^)[05], S33);
  StageH(b, c, d, a, TArray16UINT(Block^)[13], S34);
  StageH(a, b, c, d, TArray16UINT(Block^)[03], S31);
  StageH(d, a, b, c, TArray16UINT(Block^)[11], S32);
  StageH(c, d, a, b, TArray16UINT(Block^)[07], S33);
  StageH(b, c, d, a, TArray16UINT(Block^)[15], S34);

  Inc(FState[0], A);
  Inc(FState[1], B);
  Inc(FState[2], C);
  Inc(FState[3], D);
end;

function THashMD4.GetPadBuffer: TBytes;
const
  MD4Padding: array[0..63] of Byte = (
  $80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
var
  LengthInBits: UInt64;
  PadLen: Word;
begin
  Inc(FLength, FUsedBuffer);
  LengthInBits := FLength shl 3; // Size in Bits
  if FUsedBuffer < 56 then
    PadLen := 56 - FUsedBuffer
  else
    PadLen := 120 - FUsedBuffer;
  SetLength(Result, PadLen + 8);
  Move(MD4Padding[0], Result[0], PadLen);
  Move(LengthInBits, Result[PadLen], 8);
end;

procedure THashMD4.Finalize;
begin
  inherited;
  SetValueFromBuffer(@FState, HashSize);
end;

end.
