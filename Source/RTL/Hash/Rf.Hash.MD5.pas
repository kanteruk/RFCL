{ *********************************************************************** }
{ Copyright (c) 2010-2011 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.Hash.MD5;

interface

uses System.SysUtils, Rf.Types, Rf.Hash;

type

  /// <summary>
  /// Message-Digest 5 (MD5) 
  /// </summary>
  THashMD5 = class(TBlockHash)
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

{ THashMD5 }

class function THashMD5.HashType: THashType;
begin
  Result := THashType.Cryptographic;
end;

function THashMD5.HashSize: Cardinal;
begin
  Result := 16;
end;

function THashMD5.BlockSize: Cardinal;
begin
  Result := 64;
end;

procedure THashMD5.Initialize;
begin
  inherited;
  FState[0] := $67452301;
  FState[1] := $EFCDAB89;
  FState[2] := $98BADCFE;
  FState[3] := $10325476;
  FLength := 0;
end;

procedure THashMD5.UpdateBlock(const Block: Pointer);
type
  TArray16UINT = array[0..15] of Cardinal;
const
  S11 = 07;
  S12 = 12;
  S13 = 17;
  S14 = 22;
  S21 = 05;
  S22 = 09;
  S23 = 14;
  S24 = 20;
  S31 = 04;
  S32 = 11;
  S33 = 16;
  S34 = 23;
  S41 = 06;
  S42 = 10;
  S43 = 15;
  S44 = 21;

  procedure StageF(var a: Cardinal; const b, c, d, x, ac: Cardinal; const s: Byte); inline;
  begin
    a := b + RotateLeft(a + ((b and c) or ((not b) and d)) + x + ac, s);
  end;

  procedure StageG(var a: Cardinal; const b, c, d, x, ac: Cardinal; const s: Byte); inline;
  begin
    a := b + RotateLeft(a + ((b and d) or ((not d) and c)) + x + ac, s);
  end;

  procedure StageH(var a: Cardinal; const b, c, d, x, ac: Cardinal; const s: Byte); inline;
  begin
    a := b + RotateLeft(a + (b xor c xor d) + x + ac, s);
  end;

  procedure StageI(var a: Cardinal; const b, c, d, x, ac: Cardinal; const s: Byte); inline;
  begin
    a := b + RotateLeft(a + (c xor ((not d) or b)) + x + ac, s);
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
  StageF(A, B, C, D, TArray16UINT(Block^)[00], $D76AA478, S11);
  StageF(D, A, B, C, TArray16UINT(Block^)[01], $E8C7B756, S12);
  StageF(C, D, A, B, TArray16UINT(Block^)[02], $242070DB, S13);
  StageF(B, C, D, A, TArray16UINT(Block^)[03], $C1BDCEEE, S14);
  StageF(A, B, C, D, TArray16UINT(Block^)[04], $F57C0FAF, S11);
  StageF(D, A, B, C, TArray16UINT(Block^)[05], $4787C62A, S12);
  StageF(C, D, A, B, TArray16UINT(Block^)[06], $A8304613, S13);
  StageF(B, C, D, A, TArray16UINT(Block^)[07], $FD469501, S14);
  StageF(A, B, C, D, TArray16UINT(Block^)[08], $698098D8, S11);
  StageF(D, A, B, C, TArray16UINT(Block^)[09], $8B44F7AF, S12);
  StageF(C, D, A, B, TArray16UINT(Block^)[10], $FFFF5BB1, S13);
  StageF(B, C, D, A, TArray16UINT(Block^)[11], $895CD7BE, S14);
  StageF(A, B, C, D, TArray16UINT(Block^)[12], $6B901122, S11);
  StageF(D, A, B, C, TArray16UINT(Block^)[13], $FD987193, S12);
  StageF(C, D, A, B, TArray16UINT(Block^)[14], $A679438E, S13);
  StageF(B, C, D, A, TArray16UINT(Block^)[15], $49B40821, S14);

  { Stage 2 }
  StageG(A, B, C, D, TArray16UINT(Block^)[01], $F61E2562, S21);
  StageG(D, A, B, C, TArray16UINT(Block^)[06], $C040B340, S22);
  StageG(C, D, A, B, TArray16UINT(Block^)[11], $265E5A51, S23);
  StageG(B, C, D, A, TArray16UINT(Block^)[00], $E9B6C7AA, S24);
  StageG(A, B, C, D, TArray16UINT(Block^)[05], $D62F105D, S21);
  StageG(D, A, B, C, TArray16UINT(Block^)[10], $02441453, S22);
  StageG(C, D, A, B, TArray16UINT(Block^)[15], $D8A1E681, S23);
  StageG(B, C, D, A, TArray16UINT(Block^)[04], $E7D3FBC8, S24);
  StageG(A, B, C, D, TArray16UINT(Block^)[09], $21E1CDE6, S21);
  StageG(D, A, B, C, TArray16UINT(Block^)[14], $C33707D6, S22);
  StageG(C, D, A, B, TArray16UINT(Block^)[03], $F4D50D87, S23);
  StageG(B, C, D, A, TArray16UINT(Block^)[08], $455A14ED, S24);
  StageG(A, B, C, D, TArray16UINT(Block^)[13], $A9E3E905, S21);
  StageG(D, A, B, C, TArray16UINT(Block^)[02], $FCEFA3F8, S22);
  StageG(C, D, A, B, TArray16UINT(Block^)[07], $676F02D9, S23);
  StageG(B, C, D, A, TArray16UINT(Block^)[12], $8D2A4C8A, S24);

  { Stage 3 }
  StageH(A, B, C, D, TArray16UINT(Block^)[05], $FFFA3942, S31);
  StageH(D, A, B, C, TArray16UINT(Block^)[08], $8771F681, S32);
  StageH(C, D, A, B, TArray16UINT(Block^)[11], $6D9D6122, S33);
  StageH(B, C, D, A, TArray16UINT(Block^)[14], $FDE5380C, S34);
  StageH(A, B, C, D, TArray16UINT(Block^)[01], $A4BEEA44, S31);
  StageH(D, A, B, C, TArray16UINT(Block^)[04], $4BDECFA9, S32);
  StageH(C, D, A, B, TArray16UINT(Block^)[07], $F6BB4B60, S33);
  StageH(B, C, D, A, TArray16UINT(Block^)[10], $BEBFBC70, S34);
  StageH(A, B, C, D, TArray16UINT(Block^)[13], $289B7EC6, S31);
  StageH(D, A, B, C, TArray16UINT(Block^)[00], $EAA127FA, S32);
  StageH(C, D, A, B, TArray16UINT(Block^)[03], $D4EF3085, S33);
  StageH(B, C, D, A, TArray16UINT(Block^)[06], $04881D05, S34);
  StageH(A, B, C, D, TArray16UINT(Block^)[09], $D9D4D039, S31);
  StageH(D, A, B, C, TArray16UINT(Block^)[12], $E6DB99E5, S32);
  StageH(C, D, A, B, TArray16UINT(Block^)[15], $1FA27CF8, S33);
  StageH(B, C, D, A, TArray16UINT(Block^)[02], $C4AC5665, S34);

  { Stage 4 }
  StageI(A, B, C, D, TArray16UINT(Block^)[00], $F4292244, S41);
  StageI(D, A, B, C, TArray16UINT(Block^)[07], $432AFF97, S42);
  StageI(C, D, A, B, TArray16UINT(Block^)[14], $AB9423A7, S43);
  StageI(B, C, D, A, TArray16UINT(Block^)[05], $FC93A039, S44);
  StageI(A, B, C, D, TArray16UINT(Block^)[12], $655B59C3, S41);
  StageI(D, A, B, C, TArray16UINT(Block^)[03], $8F0CCC92, S42);
  StageI(C, D, A, B, TArray16UINT(Block^)[10], $FFEFF47D, S43);
  StageI(B, C, D, A, TArray16UINT(Block^)[01], $85845DD1, S44);
  StageI(A, B, C, D, TArray16UINT(Block^)[08], $6FA87E4F, S41);
  StageI(D, A, B, C, TArray16UINT(Block^)[15], $FE2CE6E0, S42);
  StageI(C, D, A, B, TArray16UINT(Block^)[06], $A3014314, S43);
  StageI(B, C, D, A, TArray16UINT(Block^)[13], $4E0811A1, S44);
  StageI(A, B, C, D, TArray16UINT(Block^)[04], $F7537E82, S41);
  StageI(D, A, B, C, TArray16UINT(Block^)[11], $BD3AF235, S42);
  StageI(C, D, A, B, TArray16UINT(Block^)[02], $2AD7D2BB, S43);
  StageI(B, C, D, A, TArray16UINT(Block^)[09], $EB86D391, S44);

  Inc(FState[0], A);
  Inc(FState[1], B);
  Inc(FState[2], C);
  Inc(FState[3], D);
end;

function THashMD5.GetPadBuffer: TBytes;
const
  MD5Padding: array[0..63] of Byte = (
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
  Move(MD5Padding[0], Result[0], PadLen);
  Move(LengthInBits, Result[PadLen], 8);
end;

procedure THashMD5.Finalize;
begin
  inherited;
  SetValueFromBuffer(@FState, HashSize);
end;

end.
