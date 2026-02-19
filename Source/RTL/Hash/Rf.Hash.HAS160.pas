{ *********************************************************************** }
{ Copyright (c) 2010-2017 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.Hash.HAS160;

interface

uses Rf.Types, Rf.SysUtils, Rf.Hash;

type

  /// <summary>
  /// HAS Hash Algorithm 160 Bit (HAS160) 
  /// </summary>
  THashHAS160 = class(TBlockHash)
  private
    FState: array[0..4] of Cardinal;
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

{ THashHAS160 }

class function THashHAS160.HashType: THashType;
begin
  Result := THashType.Cryptographic;
end;

function THashHAS160.HashSize: Cardinal;
begin
  Result := 20;
end;

function THashHAS160.BlockSize: Cardinal;
begin
  Result := 64;
end;

procedure THashHAS160.Initialize;
begin
  inherited;
  FState[0] := $67452301;
  FState[1] := $EFCDAB89;
  FState[2] := $98BADCFE;
  FState[3] := $10325476;
  FState[4] := $C3D2E1F0;
  FLength := 0;
end;

procedure THashHAS160.UpdateBlock(const Block: Pointer);
const
  cROT: array[0..19] of Byte =
    (5, 11,  7, 15,  6, 13,  8, 14,  7, 12,  9, 11,  8, 15,  6, 12,  9, 14,  5, 13);
  cTOR: array[0..19] of Byte =
    (27, 21, 25, 17, 26, 19, 24, 18, 25, 20, 23, 21, 24, 17, 26, 20, 23, 18, 27, 19);
  cNDX: array[0..79] of Byte = (
    18,  0,  1,  2,  3, 19,  4,  5, 6,  7, 16,  8,  9, 10, 11, 17, 12, 13, 14, 15,
    18,  3,  6,  9, 12, 19, 15,  2, 5,  8, 16, 11, 14,  1,  4, 17,  7, 10, 13,  0,
    18, 12,  5, 14,  7, 19,  0,  9, 2, 11, 16,  4, 13,  6, 15, 17,  8,  1, 10,  3,
    18,  7,  2, 13,  8, 19,  3, 14, 9,  4, 16, 15, 10,  5,  0, 17, 11,  6,  1, 12);
type
  TArray16UINT = array[0..15] of Cardinal;
var
  A, B, C, D, E, T: Cardinal;
  W: array[0..19] of Cardinal;
  i: Integer;
begin
  Inc(FLength, 64);

  Move(Block^, W, 64);
  {for i := 0 to 15 do
    W[i]:= TArray16UINT(Block^)[i]; }

  A := FState[0];
  B := FState[1];
  C := FState[2];
  D := FState[3];
  E := FState[4];

  W[16] := W[ 0] xor W[ 1] xor W[ 2] xor W[ 3];
  W[17] := W[ 4] xor W[ 5] xor W[ 6] xor W[ 7];
  W[18] := W[ 8] xor W[ 9] xor W[10] xor W[11];
  W[19] := W[12] xor W[13] xor W[14] xor W[15];

  for i := 0 to 19 do
  begin
    T := (RotateLeft(A, cROT[i]) or RotateRight(A, cTOR[i])) + ((B and C) or (not B and D)) + E + W[cNDX[i]];
    E := D;
    D := C;
    C := RotateLeft(B, 10) or RotateRight(B, 22);
    B := A;
    A := T;
  end;

  W[16] := W[ 3] xor W[ 6] xor W[ 9] xor W[12];
  W[17] := W[ 2] xor W[ 5] xor W[ 8] xor W[15];
  W[18] := W[ 1] xor W[ 4] xor W[11] xor W[14];
  W[19] := W[ 0] xor W[ 7] xor W[10] xor W[13];
  for i := 20 to 39 do
  begin
    T := (RotateLeft(A, cROT[i-20]) or RotateRight(A, cTOR[i-20])) + (B xor C xor D) + E + W[cNDX[i]] + $5A827999;
    E := D;
    D := C;
    C := RotateLeft(B, 17) or RotateRight(B, 15);
    B := A;
    A := T;
  end;

  W[16] := W[ 5] xor W[ 7] xor W[12] xor W[14];
  W[17] := W[ 0] xor W[ 2] xor W[ 9] xor W[11];
  W[18] := W[ 4] xor W[ 6] xor W[13] xor W[15];
  W[19] := W[ 1] xor W[ 3] xor W[ 8] xor W[10];
  for i := 40 to 59 do
  begin
    T := (RotateLeft(A, cROT[i-40]) or RotateRight(A, cTOR[i-40])) + (C xor (B or not D)) + E + W[cNDX[i]] + $6ED9EBA1;
    E := D;
    D := C;
    C := RotateLeft(B, 25) or RotateRight(B, 7);
    B := A;
    A := T;
  end;

  W[16] := W[ 2] xor W[ 7] xor W[ 8] xor W[13];
  W[17] := W[ 3] xor W[ 4] xor W[ 9] xor W[14];
  W[18] := W[ 0] xor W[ 5] xor W[10] xor W[15];
  W[19] := W[ 1] xor W[ 6] xor W[11] xor W[12];
  for i := 60 to 79 do
  begin
    T := (RotateLeft(A, cROT[i-60]) or RotateRight(A, cTOR[i-60])) + (B xor C xor D) + E + W[cNDX[i]] + $8F1BBCDC;
    E := D;
    D := C;
    C := RotateLeft(B, 30) or RotateRight(B, 2);
    B := A;
    A := T;
  end;

  Inc(FState[0], A);
  Inc(FState[1], B);
  Inc(FState[2], C);
  Inc(FState[3], D);
  Inc(FState[4], E);
end;

function THashHAS160.GetPadBuffer: TBytes;
var
  i: Word;
  LengthInBits: UInt64;
  Len: Word;
begin
  Inc(FLength, UsedBuffer);
  LengthInBits := FLength shl 3;
  if FUsedBuffer < 56 then
    Len := 56 - FUsedBuffer
  else
    Len := 120 - FUsedBuffer;
  SetLength(Result, Len + 8);
  Result[0] := $80;
  for i := 1 to Len - 1 do
    Result[i] := 0;
  Result[Len+0] := Byte(LengthInBits);
  Result[Len+1] := Byte(LengthInBits shr 8);
  Result[Len+2] := Byte(LengthInBits shr 16);
  Result[Len+3] := Byte(LengthInBits shr 24);
  Result[Len+4] := Byte(LengthInBits shr 32);
  Result[Len+5] := Byte(LengthInBits shr 40);
  Result[Len+6] := Byte(LengthInBits shr 48);
  Result[Len+7] := Byte(LengthInBits shr 56);
end;

procedure THashHAS160.Finalize;
begin
  inherited;
  SetValueFromBuffer(@FState, HashSize);
end;

end.
