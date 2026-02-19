{ *********************************************************************** }
{ Copyright (c) 2010-2017 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.Hash.SHA2;

interface

uses Rf.Types, Rf.SysUtils, Rf.Hash;

type

  /// <summary>
  /// Secure Hash Algorithm 2 (SHA2)
  /// </summary>
  THashSHA2 = class abstract(TBlockHash)
  private
    FLength: UInt64;
  public
    class function HashType: THashType; override;
  end;

{ THashSHA256 }

  THashSHA256 = class(THashSHA2)
  private
    FState: array[0..7] of DWORD;
  protected
    procedure Initialize; override;
    procedure UpdateBlock(const Block: Pointer); override;
    function GetPadBuffer: TBytes; override;
    procedure Finalize; override;
  public
    function HashSize: Cardinal; override;
    function BlockSize: Cardinal; override;
  end;

{ THashSHA224 }

  THashSHA224 = class(THashSHA256)
  protected
    procedure Initialize; override;
  public
    function HashSize: Cardinal; override;
  end;

{ THashSHA512 }

  THashSHA512 = class(THashSHA2)
  private
    FState: array[0..7] of UInt64;
  protected
    procedure Initialize; override;
    procedure UpdateBlock(const Block: Pointer); override;
    function GetPadBuffer: TBytes; override;
    procedure Finalize; override;
  public
    function HashSize: Cardinal; override;
    function BlockSize: Cardinal; override;
  end;

{ THashSHA384 }

  THashSHA384 = class(THashSHA512)
  protected
    procedure Initialize; override;
  public
    function HashSize: Cardinal; override;
  end;

{ THashSHA512_224 }

  THashSHA512_224 = class(THashSHA512)
  protected
    procedure Initialize; override;
    procedure Finalize; override;
  public
    function HashSize: Cardinal; override;
  end;

{ THashSHA512_256 }

  THashSHA512_256 = class(THashSHA512)
  protected
    procedure Initialize; override;
  public
    function HashSize: Cardinal; override;
  end;

implementation

{ THashSHA2 }

class function THashSHA2.HashType: THashType;
begin
  Result := THashType.Cryptographic;
end;

{ THashSHA256 }

function THashSHA256.HashSize: Cardinal;
begin
  Result := 32;
end;

function THashSHA256.BlockSize: Cardinal;
begin
  Result := 64;
end;

procedure THashSHA256.Initialize;
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

procedure THashSHA256.UpdateBlock(const Block: Pointer);
const
  K256: array[0..63] of DWORD = (
   $428A2F98, $71374491, $B5C0FBCF, $E9B5DBA5, $3956C25B, $59F111F1, $923F82A4, $AB1C5ED5,
   $D807AA98, $12835B01, $243185BE, $550C7DC3, $72BE5D74, $80DEB1FE, $9BDC06A7, $C19BF174,
   $E49B69C1, $EFBE4786, $0FC19DC6, $240CA1CC, $2DE92C6F, $4A7484AA, $5CB0A9DC, $76F988DA,
   $983E5152, $A831C66D, $B00327C8, $BF597FC7, $C6E00BF3, $D5A79147, $06CA6351, $14292967,
   $27B70A85, $2E1B2138, $4D2C6DFC, $53380D13, $650A7354, $766A0ABB, $81C2C92E, $92722C85,
   $A2BFE8A1, $A81A664B, $C24B8B70, $C76C51A3, $D192E819, $D6990624, $F40E3585, $106AA070,
   $19A4C116, $1E376C08, $2748774C, $34B0BCB5, $391C0CB3, $4ED8AA4A, $5B9CCA4F, $682E6FF3,
   $748F82EE, $78A5636F, $84C87814, $8CC70208, $90BEFFFA, $A4506CEB, $BEF9A3F7, $C67178F2);

type
  TArray16UINT = array[0..15] of DWORD;
var
  A, B, C, D, E, F, G, H: DWORD;
  W: array[0..63] of DWORD;
  t1, t2, s0, s1: DWORD;
  i: Integer;
begin
  Inc(FLength, FBlockSize);

  A := FState[0];
  B := FState[1];
  C := FState[2];
  D := FState[3];
  E := FState[4];
  F := FState[5];
  G := FState[6];
  H := FState[7];

  for i := 0 to 15 do
    W[i] := SwapEndian(TArray16UINT(Block^)[i]);

  for i := 16 to 63 do
  begin
    s0 := RotateRight(W[i-15], 7) xor RotateRight(W[i-15], 18) xor (W[i-15] shr 3);
    s1 := RotateRight(W[i-2], 17) xor RotateRight(W[i-2], 19) xor (W[i-2] shr 10);
    W[i] := W[i-16] + s0 + W[i-7] + s1;
  end;

  for i := 0 to 63 do
  begin
    t1 := H + ((RotateRight(E, 6) xor RotateRight(E, 11) xor RotateRight(E, 25))) +
      ((E and F) xor ((not E) and G)) + K256[i] + W[i];
    t2 := (RotateRight(A, 2) xor RotateRight(A, 13) xor RotateRight(A, 22)) +
      ((A and B) xor (A and C) xor (B and C));
    H := G;
    G := F;
    F := E;
    E := D + t1;
    D := C;
    C := B;
    B := A;
    A := t1 + t2;
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

function THashSHA256.GetPadBuffer: TBytes;
var
  i: Cardinal;
  LengthInBits: UInt64;
  Len: Cardinal;
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

procedure THashSHA256.Finalize;
begin
  inherited;
  ToBigEndian4(FState, FValue);
end;

{ THashSHA224 }

function THashSHA224.HashSize: Cardinal;
begin
  Result := 28;
end;

procedure THashSHA224.Initialize;
begin
  inherited;
  FState[0] := $C1059ED8;
  FState[1] := $367CD507;
  FState[2] := $3070DD17;
  FState[3] := $F70E5939;
  FState[4] := $FFC00B31;
  FState[5] := $68581511;
  FState[6] := $64F98FA7;
  FState[7] := $BEFA4FA4;
  FLength := 0;
end;

{ THashSHA512 }

function THashSHA512.HashSize: Cardinal;
begin
  Result := 64;
end;

function THashSHA512.BlockSize: Cardinal;
begin
  Result := 128;
end;

procedure THashSHA512.Initialize;
begin
  inherited;
  FState[0] := $6A09E667F3BCC908;
  FState[1] := $BB67AE8584CAA73B;
  FState[2] := $3C6EF372FE94F82B;
  FState[3] := $A54FF53A5F1D36F1;
  FState[4] := $510E527FADE682D1;
  FState[5] := $9B05688C2B3E6C1F;
  FState[6] := $1F83D9ABFB41BD6B;
  FState[7] := $5BE0CD19137E2179;
  FLength := 0;
end;

procedure THashSHA512.UpdateBlock(const Block: Pointer);
const
  K512: array[0..79] of UInt64 = (
    $428A2F98D728AE22, $7137449123EF65CD, $B5C0FBCFEC4D3B2F, $E9B5DBA58189DBBC,
    $3956C25BF348B538, $59F111F1B605D019, $923F82A4AF194F9B, $AB1C5ED5DA6D8118,
    $D807AA98A3030242, $12835B0145706FBE, $243185BE4EE4B28C, $550C7DC3D5FFB4E2,
    $72BE5D74F27B896F, $80DEB1FE3B1696B1, $9BDC06A725C71235, $C19BF174CF692694,
    $E49B69C19EF14AD2, $EFBE4786384F25E3, $0FC19DC68B8CD5B5, $240CA1CC77AC9C65,
    $2DE92C6F592B0275, $4A7484AA6EA6E483, $5CB0A9DCBD41FBD4, $76F988DA831153B5,
    $983E5152EE66DFAB, $A831C66D2DB43210, $B00327C898FB213F, $BF597FC7BEEF0EE4,
    $C6E00BF33DA88FC2, $D5A79147930AA725, $06CA6351E003826F, $142929670A0E6E70,
    $27B70A8546D22FFC, $2E1B21385C26C926, $4D2C6DFC5AC42AED, $53380D139D95B3DF,
    $650A73548BAF63DE, $766A0ABB3C77B2A8, $81C2C92E47EDAEE6, $92722C851482353B,
    $A2BFE8A14CF10364, $A81A664BBC423001, $C24B8B70D0F89791, $C76C51A30654BE30,
    $D192E819D6EF5218, $D69906245565A910, $F40E35855771202A, $106AA07032BBD1B8,
    $19A4C116B8D2D0C8, $1E376C085141AB53, $2748774CDF8EEB99, $34B0BCB5E19B48A8,
    $391C0CB3C5C95A63, $4ED8AA4AE3418ACB, $5B9CCA4F7763E373, $682E6FF3D6B2B8A3,
    $748F82EE5DEFB2FC, $78A5636F43172F60, $84C87814A1F0AB72, $8CC702081A6439EC,
    $90BEFFFA23631E28, $A4506CEBDE82BDE9, $BEF9A3F7B2C67915, $C67178F2E372532B,
    $CA273ECEEA26619C, $D186B8C721C0C207, $EADA7DD6CDE0EB1E, $F57D4F7FEE6ED178,
    $06F067AA72176FBA, $0A637DC5A2C898A6, $113F9804BEF90DAE, $1B710B35131C471B,
    $28DB77F523047D84, $32CAAB7B40C72493, $3C9EBE0A15C9BEBC, $431D67C49C100D4C,
    $4CC5D4BECB3E42B6, $597F299CFC657E2A, $5FCB6FAB3AD6FAEC, $6C44198C4A475817);
type
  TArray16UInt64 = array[0..15] of UInt64;
var
  A, B, C, D, E, F, G, H: UInt64;
  W: array[0..79] of UInt64;
  t0, t1, s0, s1: UInt64;
  i: Cardinal;
begin
  Inc(FLength, FBlockSize);

  A := FState[0];
  B := FState[1];
  C := FState[2];
  D := FState[3];
  E := FState[4];
  F := FState[5];
  G := FState[6];
  H := FState[7];

  for i := 0 to 15 do
    W[i] := SwapEndian(TArray16UInt64(Block^)[i]);

  for i := 16 to 79 do
  begin
    s0 := (RotateRight(W[i - 15], 1) xor RotateRight(W[i - 15], 8) xor (W[i - 15] shr 7));
    s1 := (RotateRight(W[i - 2], 19) xor RotateRight(W[i - 2], 61) xor (W[i - 2] shr 6));
    W[i] := s1 + W[i - 7] + s0 + W[i - 16];
  end;
  for i := 0 to 79 do
  begin
    t0 := H + ((RotateRight(E, 14) xor RotateRight(E, 18) xor RotateRight(E, 41))) +
      ((E and F) xor ((not E) and G)) + K512[i] + W[i];
    t1 := ((RotateRight(A, 28) xor RotateRight(A, 34) xor RotateRight(A, 39))) +
      ((A and B) xor (A and C) xor (B and C));
    H := G;
    G := F;
    F := E;
    E := D + t0;
    D := C;
    C := B;
    B := A;
    A := t0 + t1;
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

function THashSHA512.GetPadBuffer: TBytes;
var
  i: Cardinal;
  LengthInBits: UInt64;
  Len: Cardinal;
begin
  Inc(FLength, UsedBuffer);
  LengthInBits := FLength shl 3;
  if FUsedBuffer < 112 then
    Len := 112 - FUsedBuffer
  else
    Len := 240 - FUsedBuffer;
  SetLength(Result, Len + 16);
  Result[0] := $80;
  for i := 1 to Len - 1 + 8 do
    Result[i] := 0;
  Inc(Len, 8);
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

procedure THashSHA512.Finalize;
begin
  inherited;
  ToBigEndian8(FState, FValue);
end;

{ THashSHA384 }

function THashSHA384.HashSize: Cardinal;
begin
  Result := 48;
end;

procedure THashSHA384.Initialize;
begin
  inherited;
  FState[0] := $CBBB9D5DC1059ED8;
  FState[1] := $629A292A367CD507;
  FState[2] := $9159015A3070DD17;
  FState[3] := $152FECD8F70E5939;
  FState[4] := $67332667FFC00B31;
  FState[5] := $8EB44A8768581511;
  FState[6] := $DB0C2E0D64F98FA7;
  FState[7] := $47B5481DBEFA4FA4;
  FLength := 0;
end;

{ THashSHA512_224 }

function THashSHA512_224.HashSize: Cardinal;
begin
  Result := 28;
end;

procedure THashSHA512_224.Initialize;
begin
  inherited;
  FState[0] := $8C3D37C819544DA2;
  FState[1] := $73E1996689DCD4D6;
  FState[2] := $1DFAB7AE32FF9C82;
  FState[3] := $679DD514582F9FCF;
  FState[4] := $0F6D2B697BD44DA8;
  FState[5] := $77E36F7304C48942;
  FState[6] := $3F9D85A86A1D36C8;
  FState[7] := $1112E6AD91D692A1;
end;

procedure THashSHA512_224.Finalize;
begin
  SetLength(FValue, 28 + 4); // mod 8 align
  inherited;
  SetLength(FValue, HashSize);
end;

{ THashSHA512_256 }

function THashSHA512_256.HashSize: Cardinal;
begin
  Result := 32;
end;

procedure THashSHA512_256.Initialize;
begin
  inherited;
  FState[0] := $22312194FC2BF72C;
  FState[1] := $9F555FA3C84C64C2;
  FState[2] := $2393B86B6F53B151;
  FState[3] := $963877195940EABD;
  FState[4] := $96283EE2A88EFFE3;
  FState[5] := $BE5E1E2553863992;
  FState[6] := $2B0199FC2C85B8AA;
  FState[7] := $0EB72DDC81C52CA2;
end;

end.
