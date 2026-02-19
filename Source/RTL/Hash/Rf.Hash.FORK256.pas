{ *********************************************************************** }
{ Copyright (c) 2010-2017 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.Hash.FORK256;

interface

uses Rf.Types, Rf.SysUtils, Rf.Hash;

type

  /// <summary>
  /// FORK Hash Algorithm 256Bit (FORK256)
  /// </summary>
  THashFORK256 = class(TBlockHash)
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

{ THashFORK256 }

class function THashFORK256.HashType: THashType;
begin
  Result := THashType.Cryptographic;
end;

function THashFORK256.HashSize: Cardinal;
begin
  Result := 32;
end;

function THashFORK256.BlockSize: Cardinal;
begin
  Result := 64;
end;

procedure THashFORK256.Initialize;
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

procedure THashFORK256.UpdateBlock(const Block: Pointer);
type
  TArray8UINT = array[0..7] of Cardinal;

const
  Delta: array[0..15] of Cardinal = (
    $428A2F98, $71374491, $B5C0FBCF, $E9B5DBA5, $3956C25B, $59F111F1, $923F82A4, $AB1C5ED5,
    $D807AA98, $12835B01, $243185BE, $550C7DC3, $72BE5D74, $80DEB1FE, $9BDC06A7, $C19BF174);


  function Fx(const X: Cardinal): Cardinal; inline;
  begin
    Result :=  X + (RotateLeft(X, 7) xor RotateLeft(X, 22));
  end;

  function Gx(const X: Cardinal): Cardinal; inline;
  begin
    Result :=  X xor (RotateLeft(X, 13) + RotateLeft(X, 27));
  end;

  procedure Step(var Arr: TArray8UINT; const M1, M2, Delta1, Delta2: Cardinal); inline;
  var
    x1, x1d, x2, x2d, temp, g, f: Cardinal;
  begin
    x1 := Arr[0] + M1; x1d := x1 + Delta1;
    x2 := Arr[4] + M2; x2d := x2 + Delta2;
    g := Gx(x2);
    f := Fx(x2d);
    temp := Arr[7] + RotateLeft(g, 21) xor RotateLeft(f, 17);
    Arr[7] := Arr[6] + RotateLeft(g, 9) xor RotateLeft(f, 5);
    Arr[6] := Arr[5] + g xor f;
    Arr[5] := x2d;
    g := Gx(x1d);
    f := Fx(x1);
    Arr[4] := Arr[3] + RotateLeft(f, 17) xor RotateLeft(g, 21);
    Arr[3] := Arr[2] + RotateLeft(f, 5) xor RotateLeft(g, 9);
    Arr[2] := Arr[1] + f xor g;
    Arr[1] := x1d;
    Arr[0] := temp;
  end;

type
  TArray16UINT = array[0..15] of Cardinal;
var
  W: array[0..15] of Cardinal;
  i: Integer;
  tmp1, tmp2, tmp3, tmp4: TArray8UINT;
begin
  Inc(FLength, 64);

  for i := 0 to 15 do
    W[i] := SwapEndian(TArray16UINT(Block^)[i]);

  for i := 0 to 7 do
  begin
    tmp1[i] := FState[i];
    tmp2[i] := FState[i];
    tmp3[i] := FState[i];
    tmp4[i] := FState[i];
  end;

  // Branch 1
  Step(tmp1, W[00], W[01], Delta[00], Delta[01]);
  Step(tmp1, W[02], W[03], Delta[02], Delta[03]);
  Step(tmp1, W[04], W[05], Delta[04], Delta[05]);
  Step(tmp1, W[06], W[07], Delta[06], Delta[07]);
  Step(tmp1, W[08], W[09], Delta[08], Delta[09]);
  Step(tmp1, W[10], W[11], Delta[10], Delta[11]);
  Step(tmp1, W[12], W[13], Delta[12], Delta[13]);
  Step(tmp1, W[14], W[15], Delta[14], Delta[15]);
  // Branch 2
  Step(tmp2, W[14], W[15], Delta[15], Delta[14]);
  Step(tmp2, W[11], W[09], Delta[13], Delta[12]);
  Step(tmp2, W[08], W[10], Delta[11], Delta[10]);
  Step(tmp2, W[03], W[04], Delta[09], Delta[08]);
  Step(tmp2, W[02], W[13], Delta[07], Delta[06]);
  Step(tmp2, W[00], W[05], Delta[05], Delta[04]);
  Step(tmp2, W[06], W[07], Delta[03], Delta[02]);
  Step(tmp2, W[12], W[01], Delta[01], Delta[00]);
  // Branch 3
  Step(tmp3, W[07], W[06], Delta[01], Delta[00]);
  Step(tmp3, W[10], W[14], Delta[03], Delta[02]);
  Step(tmp3, W[13], W[02], Delta[05], Delta[04]);
  Step(tmp3, W[09], W[12], Delta[07], Delta[06]);
  Step(tmp3, W[11], W[04], Delta[09], Delta[08]);
  Step(tmp3, W[15], W[08], Delta[11], Delta[10]);
  Step(tmp3, W[05], W[00], Delta[13], Delta[12]);
  Step(tmp3, W[01], W[03], Delta[15], Delta[14]);
  // Branch 4
  Step(tmp4, W[05], W[12], Delta[14], Delta[15]);
  Step(tmp4, W[01], W[08], Delta[12], Delta[13]);
  Step(tmp4, W[15], W[00], Delta[10], Delta[11]);
  Step(tmp4, W[13], W[11], Delta[08], Delta[09]);
  Step(tmp4, W[03], W[10], Delta[06], Delta[07]);
  Step(tmp4, W[09], W[02], Delta[04], Delta[05]);
  Step(tmp4, W[07], W[14], Delta[02], Delta[03]);
  Step(tmp4, W[04], W[06], Delta[00], Delta[01]);

  for i := 0 to 7 do
    Inc(FState[i], (tmp1[i] + tmp2[i]) xor (tmp3[i] + tmp4[i]));
end;

function THashFORK256.GetPadBuffer: TBytes;
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

procedure THashFORK256.Finalize;
begin
  inherited;
  ToBigEndian4(FState, FValue);
end;

end.
