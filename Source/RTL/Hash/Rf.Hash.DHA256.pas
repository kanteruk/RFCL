{ *********************************************************************** }
{ Copyright (c) 2010-2011 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.Hash.DHA256;

interface

uses Rf.Types, Rf.SysUtils, Rf.Hash;

type

  /// <summary>
  /// Double Hash Algorithm 256Bit (DHA256) 
  /// </summary>
  THashDHA256 = class(TBlockHash)
  private
    FState: array[0..7] of Cardinal;
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

const
  cK: array[0..63] of Cardinal = (
    $428A2F98, $71374491, $B5C0FBCF, $E9B5DBA5, $3956C25B,
    $59F111F1, $923F82A4, $AB1C5ED5, $D807AA98, $12835B01,
    $243185BE, $550C7DC3, $72BE5D74, $80DEB1FE, $9BDC06A7,
    $C19BF174, $E49B69C1, $EFBE4786, $0FC19DC6, $240CA1CC,
    $2DE92C6F, $4A7484AA, $5CB0A9DC, $76F988DA, $983E5152,
    $A831C66D, $B00327C8, $BF597FC7, $C6E00BF3, $D5A79147,
    $06CA6351, $14292967, $27B70A85, $2E1B2138, $4D2C6DFC,
    $53380D13, $650A7354, $766A0ABB, $81C2C92E, $92722C85,
    $A2BFE8A1, $A81A664B, $C24B8B70, $C76C51A3, $D192E819,
    $D6990624, $F40E3585, $106AA070, $19A4C116, $1E376C08,
    $2748774C, $34B0BCB5, $391C0CB3, $4ED8AA4A, $5B9CCA4F,
    $682E6FF3, $748F82EE, $78A5636F, $84C87814, $8CC70208,
    $90BEFFFA, $A4506CEB, $BEF9A3F7, $C67178F2);

{ THashDHA256 }

class function THashDHA256.HashType: THashType;
begin
  Result := THashType.Cryptographic;
end;

function THashDHA256.HashSize: Cardinal;
begin
  Result := 32;
end;

function THashDHA256.BlockSize: Cardinal;
begin
  Result := 64;
end;

procedure THashDHA256.Initialize;
begin
  inherited;
  FState[0] := $6A09E667;
  FState[1] := $BB67AE85;
  FState[2] := $3C6EF372;
  FState[3] := $A54FF53A;
  FState[4] := $510E527F;
  FState[5] := $9B05688C;
  FState[6] := $1F83D9AB;
  FState[7] := $5BE0CD19;
  FLength := 0;
end;

procedure THashDHA256.UpdateBlock(const Block: Pointer);
type
  PArray16UINT = ^TArray16UINT;
  TArray16UINT = array[0..15] of Cardinal;
var
  A, B, C, D, E, F, G, H: Cardinal;
  W: array[0..63] of Cardinal;
  t1, t2, i: Cardinal;
  PW: PArray16UINT;
begin
  Inc(FLength, 64);

  A := FState[0];
  B := FState[1];
  C := FState[2];
  D := FState[3];
  E := FState[4];
  F := FState[5];
  G := FState[6];
  H := FState[7];
  PW := Block;

  for i := 0 to 15 do
    W[i] := SwapEndian(PW[i]);

  for i := 16 to 63 do
  begin
    w[i] := (((w[i-15] shl 13) or RotateRight(w[i-15], 19)) xor
      ((w[i-15] shl 27) or RotateRight(w[i-15], 5)) xor w[i-15]) +
      (((w[i-1] shl 7) or (RotateRight(w[i-1], 25))) xor
      ((w[i-1] shl 22) or (RotateRight(w[i-1], 10))) xor w[i-1]) + w[i-9] + w[i-16];
  end;

  for i := 0 to 63 do
  begin
    t1 := (((h shl 19) or RotateRight(h, 13)) xor ((h shl 29) or RotateRight(h, 3)) xor h)
      + (f and g xor g and h xor f and h) + e + cK[i] + w[i];
    t2 := (((d shl 11) or RotateRight(d, 21)) xor ((d shl 25) or RotateRight(d, 7)) xor d)
      + (not b and d xor b and c) + a + cK[i] + w[i];
    A := B;
    B := C shl 17 or RotateRight(C, 15);
    C := D;
    D := t1;
    E := F;
    F := G shl 2 or RotateRight(G, 30);
    G := H;
    H := t2;
  end;

  Inc(FState[0], A);
  Inc(FState[1], B);
  Inc(FState[2], C);
  Inc(FState[3], D);
  Inc(FState[4], E);
  Inc(FState[5], F);
  Inc(FState[6], G);
  Inc(FState[7], H);
end;

function THashDHA256.GetPadBuffer: TBytes;
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

procedure THashDHA256.Finalize;
begin
  inherited;
  ToBigEndian4(FState, FValue);
end;

end.
