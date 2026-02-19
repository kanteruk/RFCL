{ *********************************************************************** }
{ Copyright (c) 2010-2014 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.Hash.RIPEMD;

interface

uses Rf.Types, Rf.SysUtils, Rf.Hash;

type

  /// <summary>
  /// RACE Integrity Primitives Evaluation Message Digest 320 bit (RIPEMD320)
  /// </summary>
{ THashRIPEMDAbstract }

  THashRIPEMDAbstract = class abstract(TBlockHash)
  private
    FLength: UInt64;
  protected
    function GetPadBuffer: TBytes; override;
  public
    class function HashType: THashType; override;
    function BlockSize: Cardinal; override;
  end;

{ THashRIPEMD128 }

  THashRIPEMD128 = class(THashRIPEMDAbstract)
  private
    FState: array[0..3] of LongWord;
  protected
    procedure Initialize; override;
    procedure UpdateBlock(const BlockBuf: Pointer); override;
    procedure Finalize; override;
  public
    function HashSize: Cardinal; override;
  end;

{ THashRIPEMD160 }

  THashRIPEMD160 = class(THashRIPEMDAbstract)
  private
    FState: array[0..4] of LongWord;
  protected
    procedure Initialize; override;
    procedure UpdateBlock(const BlockBuf: Pointer); override;
    procedure Finalize; override;
  public
    function HashSize: Cardinal; override;
  end;

{ THashRIPEMD256 }

  THashRIPEMD256 = class(THashRIPEMDAbstract)
  private
    FState: array[0..7] of LongWord;
  protected
    procedure Initialize; override;
    procedure UpdateBlock(const BlockBuf: Pointer); override;
    procedure Finalize; override;
  public
    function HashSize: Cardinal; override;
  end;

{ THashRIPEMD320 }

  THashRIPEMD320 = class(THashRIPEMDAbstract)
  private
    FState: array[0..9] of LongWord;
  protected
    procedure Initialize; override;
    procedure UpdateBlock(const BlockBuf: Pointer); override;
    procedure Finalize; override;
  public
    function HashSize: Cardinal; override;
  end;

implementation

const
  cR: array[0..79] of Byte  = (
    0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
    7,  4, 13,  1, 10,  6, 15,  3, 12,  0,  9,  5,  2, 14, 11,  8,
    3, 10, 14,  4,  9, 15,  8,  1,  2,  7,  0,  6, 13, 11,  5, 12,
    1,  9, 11, 10,  0,  8, 12,  4, 13,  3,  7, 15, 14,  5,  6,  2,
    4,  0,  5,  9,  7, 12,  2, 10, 14,  1,  3,  8, 11,  6, 15, 13);

  cRp: array[0..79] of Byte  = (
    5, 14,  7,  0,  9,  2, 11,  4, 13,  6, 15,  8,  1, 10,  3, 12,
    6, 11,  3,  7,  0, 13,  5, 10, 14, 15,  8, 12,  4,  9,  1,  2,
    15, 5,  1,  3,  7, 14,  6,  9, 11,  8, 12,  2, 10,  0,  4, 13,
    8,  6,  4,  1,  3, 11, 15,  0,  5, 12,  2, 13,  9,  7, 10, 14,
    12,15, 10,  4,  1,  5,  8,  7,  6,  2, 13, 14,  0,  3,  9, 11);

  cS: array[0..79] of Byte  = (
    11, 14, 15, 12,  5,  8,  7,  9, 11, 13, 14, 15,  6,  7,  9,  8,
     7,  6,  8, 13, 11,  9,  7, 15,  7, 12, 15,  9, 11,  7, 13, 12,
    11, 13,  6,  7, 14,  9, 13, 15, 14,  8, 13,  6,  5, 12,  7,  5,
    11, 12, 14, 15, 14, 15,  9,  8,  9, 14,  5,  6,  8,  6,  5, 12,
     9, 15,  5, 11,  6,  8, 13, 12,  5, 12, 13, 14, 11,  8,  5,  6);

  cSp: array[0..79] of Byte  = (
     8,  9,  9, 11, 13, 15, 15,  5,  7,  7,  8, 11, 14, 14, 12,  6,
     9, 13, 15,  7, 12,  8,  9, 11,  7,  7, 12,  7,  6, 15, 13, 11,
     9,  7, 15, 11,  8,  6,  6, 14, 12, 13,  5, 14, 13, 13,  7,  5,
    15,  5,  8, 11, 14, 14,  6, 14,  6,  9, 12,  9, 12,  5, 15,  8,
     8,  5, 12,  9, 12,  5, 14,  6,  8, 13,  6,  5, 15, 13, 11, 11);

{ THashRIPEMDAbstract }

class function THashRIPEMDAbstract.HashType: THashType;
begin
  Result := THashType.Cryptographic;
end;

function THashRIPEMDAbstract.BlockSize: Cardinal;
begin
  Result := 64;
end;

function THashRIPEMDAbstract.GetPadBuffer: TBytes;
var
  LengthInBits: UInt64;
  i, PadLen: Word;
begin
  Inc(FLength, FUsedBuffer);
  LengthInBits := FLength shl 3; // Size in bits
  if FUsedBuffer < 56 then
    PadLen := 56 - FUsedBuffer
  else
    PadLen := 120 - FUsedBuffer;
  SetLength(Result, PadLen + 8);
  Result[0] := $80;
  for i := 1 to PadLen - 1 do
    Result[i] := 0;
  PUInt64(@Result[PadLen])^ := LengthInBits;
end;

{ THashRIPEMD128 }

function THashRIPEMD128.HashSize: Cardinal;
begin
  Result := 16;
end;

procedure THashRIPEMD128.Initialize;
begin
  inherited;
  FState[0] := $67452301;
  FState[1] := $EFCDAB89;
  FState[2] := $98BADCFE;
  FState[3] := $10325476;
  FLength := 0;
end;

procedure THashRIPEMD128.UpdateBlock(const BlockBuf: Pointer);
type
  PArray16UINT = ^TArray16UINT;
  TArray16UINT = array[0..15] of LongWord;
var
  Block: PArray16UINT;
  A, B, C, D, Ap, Bp, Cp, Dp, T: LongWord;
  i: Byte;
begin
  Inc(FLength, 64);

  Block := BlockBuf;
  A := FState[0];
  B := FState[1];
  C := FState[2];
  D := FState[3];

  Ap := A;
  Bp := B;
  Cp := C;
  Dp := D;

  for i := 0 to 15 do
  begin
    T := A + (B xor C xor D) + Block^[i];
    A := D;
    D := C;
    C := B;
    B := RotateLeft(T, cS[i]);

    T  := Ap + ((Bp and Dp) or (Cp and not Dp)) + Block^[cRp[i]] + $50A28BE6;
    Ap := Dp;
    Dp := Cp;
    Cp := Bp;
    Bp := RotateLeft(T, cSp[i]);
  end;
  for i := 16 to 31 do
  begin
    T := A + ((B and C) or (not B and D)) + Block^[cR[i]] + $5A827999;
    A := D;
    D := C;
    C := B;
    B := RotateLeft(T, cS[i]);

    T  := Ap + ((Bp or not Cp) xor Dp) + Block^[cRp[i]] + $5C4DD124;
    Ap := Dp;
    Dp := Cp;
    Cp := Bp;
    Bp := RotateLeft(T, cSp[i]);
  end;
  for i := 32 to 47 do
  begin
    T := A + ((B or not C) xor D) + Block^[cR[i]] + $6ED9EBA1;
    A := D;
    D := C;
    C := B;
    B := RotateLeft(T, cS[i]);

    T  := Ap + ((Bp and Cp) or (not Bp and Dp)) + Block^[cRp[i]] + $6D703EF3;
    Ap := Dp;
    Dp := Cp;
    Cp := Bp;
    Bp := RotateLeft(T, cSp[i]);
  end;
  for i := 48 to 63 do
  begin
    T := A + ((B and D) or (C and not D)) + Block^[cR[i]] + $8F1BBCDC;
    A := D;
    D := C;
    C := B;
    B := RotateLeft(T, cS[i]);

    T := Ap + (Bp xor Cp xor Dp) + Block^[cRp[i]];
    Ap := Dp;
    Dp := Cp;
    Cp := Bp;
    Bp := RotateLeft(T, cSp[i]);
  end;

  T := FState[1] + C + Dp;
  FState[1] := FState[2]+ D + Ap;
  FState[2] := FState[3] + A + Bp;
  FState[3] := FState[0] + B + Cp;
  FState[0] := T;
end;

procedure THashRIPEMD128.Finalize;
begin
  inherited;
  SetValueFromBuffer(@FState, 16);
end;

{ THashRIPEMD160 }

function THashRIPEMD160.HashSize: Cardinal;
begin
  Result := 20;
end;

procedure THashRIPEMD160.Initialize;
begin
  inherited;
  FState[0] := $67452301;
  FState[1] := $EFCDAB89;
  FState[2] := $98BADCFE;
  FState[3] := $10325476;
  FState[4] := $C3D2E1F0;
  FLength := 0;
end;

procedure THashRIPEMD160.UpdateBlock(const BlockBuf: Pointer);
type
  PArray16UINT = ^TArray16UINT;
  TArray16UINT = array[0..15] of LongWord;
var
  Block: PArray16UINT;
  A, B, C, D, E, Ap, Bp, Cp, Dp, Ep, T: LongWord;
  i: Byte;
begin
  Inc(FLength, 64);
  
  Block := BlockBuf;
  A := FState[0];
  B := FState[1];
  C := FState[2];
  D := FState[3];
  E := FState[4];

  Ap := A;
  Bp := B;
  Cp := C;
  Dp := D;
  Ep := E;

  for i := 0 to 15 do
  begin
    T := A + (B xor C xor D) + Block^[i];
    A := E;
    E := D;
    D := RotateLeft(C, 10);
    C := B;
    B := RotateLeft(T, cS[i]) + A;

    T := Ap + (Bp xor (Cp or not Dp)) + Block^[cRp[i]] + $50A28BE6;
    Ap := Ep;
    Ep := Dp;
    Dp := RotateLeft(Cp, 10);
    Cp := Bp;
    Bp := RotateLeft(T, cSp[i]) + Ap;
  end;
  for i := 16 to 31 do
  begin
    T := A + ((B and C) or (not B and D)) + Block^[cR[i]] + $5A827999;
    A := E;
    E := D;
    D := RotateLeft(C, 10);
    C := B;
    B := RotateLeft(T, cS[i]) + A;

    T := Ap + ((Bp and Dp) or (Cp and not Dp)) + Block^[cRp[i]] + $5C4DD124;
    Ap := Ep;
    Ep := Dp;
    Dp := RotateLeft(Cp, 10);
    Cp := Bp;
    Bp := RotateLeft(T, cSp[i]) + Ap;
  end;
  for i := 32 to 47 do
  begin
    T := A + ((B or not C) xor D) + Block^[cR[i]] + $6ED9EBA1;
    A := E;
    E := D;
    D := RotateLeft(C, 10);
    C := B;
    B := RotateLeft(T, cS[i]) + A;

    T := Ap + ((Bp or not Cp) xor Dp) + Block^[cRp[i]] + $6D703EF3;
    Ap := Ep;
    Ep := Dp;
    Dp := RotateLeft(Cp, 10);
    Cp := Bp;
    Bp := RotateLeft(T, cSp[i]) + Ap;
  end;
  for i := 48 to 63 do
  begin
    T := A + ((B and D) or (C and not D)) + Block^[cR[i]] + $8F1BBCDC;
    A := E;
    E := D;
    D := RotateLeft(C, 10);
    C := B;
    B := RotateLeft(T, cS[i]) + A;

    T := Ap + ((Bp and Cp) or (not Bp and Dp)) + Block^[cRp[i]] + $7A6D76E9;
    Ap := Ep;
    Ep := Dp;
    Dp := RotateLeft(Cp, 10);
    Cp := Bp;
    Bp := RotateLeft(T, cSp[i]) + Ap;
  end;
  for i := 64 to 79 do
  begin
    T := A + (B xor (C or not D)) + Block^[cR[i]] + $A953FD4E;
    A := E;
    E := D;
    D := RotateLeft(C, 10);
    C := B;
    B := RotateLeft(T, cS[i]) + A;

    T := Ap + (Bp xor Cp xor Dp) + Block^[cRp[i]];
    Ap := Ep;
    Ep := Dp;
    Dp := RotateLeft(Cp, 10);
    Cp := Bp;
    Bp := RotateLeft(T, cSp[i]) + Ap;
  end;

  T := FState[1] + C + Dp;
  FState[1] := FState[2] + D + Ep;
  FState[2] := FState[3] + E + Ap;
  FState[3] := FState[4] + A + Bp;
  FState[4] := FState[0] + B + Cp;
  FState[0] := T;
end;

procedure THashRIPEMD160.Finalize;
begin
  inherited;
  SetValueFromBuffer(@FState, 20);
end;

{ THashRIPEMD256 }

function THashRIPEMD256.HashSize: Cardinal;
begin
  Result := 32;
end;

procedure THashRIPEMD256.Initialize;
begin
  inherited;
  FState[0] := $67452301;
  FState[1] := $EFCDAB89;
  FState[2] := $98BADCFE;
  FState[3] := $10325476;
  FState[4] := $76543210;
  FState[5] := $FEDCBA98;
  FState[6] := $89ABCDEF;
  FState[7] := $01234567;
  FLength := 0;
end;

procedure THashRIPEMD256.UpdateBlock(const BlockBuf: Pointer);
type
  PArray16UINT = ^TArray16UINT;
  TArray16UINT = array[0..15] of LongWord;
var
  Block: PArray16UINT;
  A, B, C, D, E, F, G, H, T: LongWord;
  i: Byte;
begin
  Inc(FLength, 64);

  Block := BlockBuf;
  A := FState[0];
  B := FState[1];
  C := FState[2];
  D := FState[3];
  E := FState[4];
  F := FState[5];
  G := FState[6];
  H := FState[7];

  for i := 0 to 15 do
  begin
    T := A + (B xor C xor D) + Block^[i];
    A := D;
    D := C;
    C := B;
    B := RotateLeft(T, cS[i]);

    T  := E + ((F and H) or (G and not H)) + Block^[cRp[i]] + $50A28BE6;
    E := H;
    H := G;
    G := F;
    F := RotateLeft(T, cSp[i]);
  end;
  T := A;
  A := E;
  E := T;
  for i := 16 to 31 do
  begin
    T := A + ((B and C) or (not B and D)) + Block^[cR[i]] + $5A827999;
    A := D;
    D := C;
    C := B;
    B := RotateLeft(T, cS[i]);

    T  := E + ((F or not G) xor H) + Block^[cRp[i]] + $5C4DD124;
    E := H;
    H := G;
    G := F;
    F := RotateLeft(T, cSp[i]);
  end;
  T := B;
  B := F;
  F := T;
  for i := 32 to 47 do
  begin
    T := A + ((B or not C) xor D) + Block^[cR[i]] + $6ED9EBA1;
    A := D;
    D := C;
    C := B;
    B := RotateLeft(T, cS[i]);

    T  := E + ((F and G) or (not F and H)) + Block^[cRp[i]] + $6D703EF3;
    E := H;
    H := G;
    G := F;
    F := RotateLeft(T, cSp[i]);
  end;
  T := C;
  C := G;
  G := T;
  for i := 48 to 63 do
  begin
    T := A + ((B and D) or (C and not D)) + Block^[cR[i]] + $8F1BBCDC;
    A := D;
    D := C;
    C := B;
    B := RotateLeft(T, cS[i]);

    T := E + (F xor G xor H) + Block^[cRp[i]];
    E := H;
    H := G;
    G := F;
    F := RotateLeft(T, cSp[i]);
  end;
  T := D;
  D := H;
  H := T;

  Inc(FState[0], A);
  Inc(FState[1], B);
  Inc(FState[2], C);
  Inc(FState[3], D);
  Inc(FState[4], E);
  Inc(FState[5], F);
  Inc(FState[6], G);
  Inc(FState[7], H);
end;

procedure THashRIPEMD256.Finalize;
begin
  inherited;
  SetValueFromBuffer(@FState, 32);
end;

{ THashRIPEMD320 }

function THashRIPEMD320.HashSize: Cardinal;
begin
  Result := 40;
end;

procedure THashRIPEMD320.Initialize;
begin
  inherited;
  FState[0] := $67452301;
  FState[1] := $EFCDAB89;
  FState[2] := $98BADCFE;
  FState[3] := $10325476;
  FState[4] := $C3D2E1F0;
  FState[5] := $76543210;
  FState[6] := $FEDCBA98;
  FState[7] := $89ABCDEF;
  FState[8] := $01234567;
  FState[9] := $3C2D1E0F;
  FLength := 0;
end;

procedure THashRIPEMD320.UpdateBlock(const BlockBuf: Pointer);
type
  PArray16UINT = ^TArray16UINT;
  TArray16UINT = array[0..15] of LongWord;
var
  Block: PArray16UINT;
  A, B, C, D, E, F, G, H, I, J, T: LongWord;
  Index: Byte;
begin
  Inc(FLength, 64);
  Block := BlockBuf;

  A := FState[0];
  B := FState[1];
  C := FState[2];
  D := FState[3];
  E := FState[4];
  F := FState[5];
  G := FState[6];
  H := FState[7];
  I := FState[8];
  J := FState[9];

  for Index := 0 to 15 do
  begin
    T := A + (B xor C xor D) + Block^[Index];
    A := E;
    E := D;
    D := RotateLeft(C, 10);
    C := B;
    B := RotateLeft(T, cS[Index]) + A;

    T := F + (G xor (H or not I)) + Block^[cRp[Index]] + $50A28BE6;
    F := J;
    J := I;
    I := RotateLeft(H, 10);
    H := G;
    G := RotateLeft(T, cSp[Index]) + F;
  end;
  T := B;
  B := G;
  G := T;
  for Index := 16 to 31 do
  begin
    T := A + ((B and C) or (not B and D)) + Block^[cR[Index]] + $5A827999;
    A := E;
    E := D;
    D := RotateLeft(C, 10);
    C := B;
    B := RotateLeft(T, cS[Index]) + A;

    T := F + ((G and I) or (H and not I)) + Block^[cRp[Index]] + $5C4DD124;
    F := J;
    J := I;
    I := RotateLeft(H, 10);
    H := G;
    G := RotateLeft(T, cSp[Index]) + F;
  end;
  T := D;
  D := I;
  I := T;
  for Index := 32 to 47 do
  begin
    T := A + ((B or not C) xor D) + Block^[cR[Index]] + $6ED9EBA1;
    A := E;
    E := D;
    D := RotateLeft(C, 10);
    C := B;
    B := RotateLeft(T, cS[Index]) + A;

    T := F + ((G or not H) xor I) + Block^[cRp[Index]] + $6D703EF3;
    F := J;
    J := I;
    I := RotateLeft(H, 10);
    H := G;
    G := RotateLeft(T, cSp[Index]) + F;
  end;
  T := A;
  A := F;
  F := T;
  for Index := 48 to 63 do
  begin
    T := A + ((B and D) or (C and not D)) + Block^[cR[Index]] + $8F1BBCDC;
    A := E;
    E := D;
    D := RotateLeft(C, 10);
    C := B;
    B := RotateLeft(T, cS[Index]) + A;

    T := F + ((G and H) or (not G and I)) + Block^[cRp[Index]] + $7A6D76E9;
    F := J;
    J := I;
    I := RotateLeft(H, 10);
    H := G;
    G := RotateLeft(T, cSp[Index]) + F;
  end;
  T := C;
  C := H;
  H := T;
  for Index := 64 to 79 do
  begin
    T := A + (B xor (C or not D)) + Block^[cR[Index]] + $A953FD4E;
    A := E;
    E := D;
    D := RotateLeft(C, 10);
    C := B;
    B := RotateLeft(T, cS[Index]) + A;

    T := F + (G xor H xor I) + Block^[cRp[Index]];
    F := J;
    J := I;
    I := RotateLeft(H, 10);
    H := G;
    G := RotateLeft(T, cSp[Index]) + F;
  end;
  T := E;
  E := J;
  J := T;

  Inc(FState[0], A);
  Inc(FState[1], B);
  Inc(FState[2], C);
  Inc(FState[3], D);
  Inc(FState[4], E);
  Inc(FState[5], F);
  Inc(FState[6], G);
  Inc(FState[7], H);
  Inc(FState[8], I);
  Inc(FState[9], J);
end;

procedure THashRIPEMD320.Finalize;
begin
  inherited;
  SetValueFromBuffer(@FState, 40);
end;

end.
