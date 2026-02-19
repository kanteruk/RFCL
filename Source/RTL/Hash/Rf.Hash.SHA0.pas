{ *********************************************************************** }
{ Copyright (c) 2010-2011 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.Hash.SHA0;

interface

uses Rf.Types, Rf.SysUtils, Rf.Hash;

type

  /// <summary>
  /// Secure Hash Algorithm 0 (SHA0)
  /// </summary>
  THashSHA0 = class(TBlockHash)
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

{ THashSHA0 }

class function THashSHA0.HashType: THashType;
begin
  Result := THashType.Cryptographic;
end;

function THashSHA0.HashSize: Cardinal;
begin
  Result := 20;
end;

function THashSHA0.BlockSize: Cardinal;
begin
  Result := 64;
end;

procedure THashSHA0.Initialize;
begin
  inherited;
  FState[0] := $67452301;
  FState[1] := $EFCDAB89;
  FState[2] := $98BADCFE;
  FState[3] := $10325476;
  FState[4] := $C3D2E1F0;
  FLength := 0;
end;

procedure THashSHA0.UpdateBlock(const Block: Pointer);
type
  TArray16UINT = array[0..15] of Cardinal;
var
  A, B, C, D, E, T: Cardinal;
  W: array[0..79] of Cardinal;
  i: Integer;
begin
  Inc(FLength, 64);

  for i := 0 to 15 do
    W[i]:= SwapEndian(TArray16UINT(Block^)[i]);
  for i := 16 to 79 do
    W[i]:= W[i-3] xor W[i-8] xor W[i-14] xor W[i-16];

  A := FState[0];
  B := FState[1];
  C := FState[2];
  D := FState[3];
  E := FState[4];

  for i := 0 to 19 do
  begin
    T := RotateLeft(A,5) + (D xor (B and (C xor D))) + E + W[i] + $5A827999;
    E := D;
    D := C;
    C := RotateLeft(B,30);
    B := A;
    A := T;
  end;
  for i := 20 to 39 do
  begin
    T := RotateLeft(A,5) + (B xor C xor D) + E + W[i] + $6ED9EBA1;
    E := D;
    D := C;
    C := RotateLeft(B,30);
    B := A;
    A := T;
  end;
  for i := 40 to 59 do
  begin
    T := RotateLeft(A,5) + ((B and C) or (D and (B or C))) + E + W[i] + $8F1BBCDC;
    E := D;
    D := C;
    C := RotateLeft(B,30);
    B := A;
    A := T;
  end;
  for i := 60 to 79 do
  begin
    T := RotateLeft(A,5) + (B xor C xor D) + E + W[i] + $CA62C1D6;
    E := D;
    D := C;
    C := RotateLeft(B,30);
    B := A;
    A := T;
  end;

  Inc(FState[0], A);
  Inc(FState[1], B);
  Inc(FState[2], C);
  Inc(FState[3], D);
  Inc(FState[4], E);
end;

function THashSHA0.GetPadBuffer: TBytes;
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
  Result[Len+0] := Byte(LengthInBits shr 56);
  Result[Len+1] := Byte(LengthInBits shr 58);
  Result[Len+2] := Byte(LengthInBits shr 50);
  Result[Len+3] := Byte(LengthInBits shr 32);
  Result[Len+4] := Byte(LengthInBits shr 24);
  Result[Len+5] := Byte(LengthInBits shr 16);
  Result[Len+6] := Byte(LengthInBits shr 8);
  Result[Len+7] := Byte(LengthInBits);
//  PUInt64(@Result[PadLen])^ := LengthInBits;
end;

procedure THashSHA0.Finalize;
begin
  inherited;
  ToBigEndian4(FState, FValue);
end;

end.
