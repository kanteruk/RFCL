{ *********************************************************************** }
{ Copyright (c) 2010-2017 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.Hash.Whirpool;

{$SCOPEDENUMS ON}

interface

uses Rf.Types, Rf.SysUtils, Rf.Hash;

type

  /// <summary>
  /// Whirpool Hash Algorithm 512Bit
  /// </summary>
  THashWhirpoolAbstract = class(TBlockHash)
  private
    FState: array[0..7] of UInt64;
    FLength: UInt64;
  protected
    procedure Initialize; override;
    procedure Finalize; override;
    function GetPadBuffer: TBytes; override;
  public
    class function HashType: THashType; override;
    function BlockSize: Cardinal; override;
  end;

{ THashWhirpool0 }

  THashWhirpool0 = class(THashWhirpoolAbstract)
  private
    FT0, FT1, FT2, FT3, FT4, FT5, FT6, FT7: array[0..255] of UInt64;
    FRC: array[0..9] of UInt64;
  protected
    procedure UpdateBlock(const Block: Pointer); override;
  public
    constructor Create; virtual;

    function HashSize: Cardinal; override;
  end;

{ THashWhirpool }

  THashWhirpoolModification = (Whirpool1, Whirpool2);

  THashWhirpool = class(THashWhirpoolAbstract)
  private
    FT0, FT1, FT2, FT3, FT4, FT5, FT6, FT7: array[0..255] of UInt64;
    FRC: array[0..9] of UInt64;
    FModificationType: THashWhirpoolModification;
  protected
    procedure UpdateBlock(const Block: Pointer); override;
  public
    constructor Create(const AModificationType: THashWhirpoolModification = THashWhirpoolModification.Whirpool2); virtual;
    property ModificationType: THashWhirpoolModification read FModificationType;
    function HashSize: Cardinal; override;
  end;

implementation

const
  SD_0: array[0..127] of Word = (
    $68D0, $EB2B, $489D, $6AE4, $E3A3, $5681, $7DF1, $859E,
    $2C8E, $78CA, $17A9, $61D5, $5D0B, $8C3C, $7751, $2242,
    $3F54, $4180, $CC86, $B318, $2E57, $0662, $F436, $D16B,
    $1B65, $7510, $DA49, $26F9, $CB66, $E7BA, $AE50, $52AB,
    $05F0, $0D73, $3B04, $20FE, $DDF5, $B45F, $0AB5, $C0A0,
    $71A5, $2D60, $7293, $3908, $8321, $5C87, $B1E0, $00C3,
    $1291, $8A02, $1CE6, $45C2, $C4FD, $BF44, $A14C, $33C5,
    $8423, $7CB0, $2515, $3569, $FF94, $4D70, $A2AF, $CDD6,
    $6CB7, $F809, $F367, $A4EA, $ECB6, $D4D2, $141E, $E124,
    $38C6, $DB4B, $7A3A, $DE5E, $DF95, $FCAA, $D7CE, $070F,
    $3D58, $9A98, $9CF2, $A711, $7E8B, $4303, $E2DC, $E5B2,
    $4EC7, $6DE9, $2740, $D837, $928F, $011D, $533E, $59C1,
    $4F32, $16FA, $74FB, $639F, $341A, $2A5A, $8DC9, $CFF6,
    $9028, $889B, $310E, $BD4A, $E896, $A60C, $C879, $BCBE,
    $EF6E, $4697, $5BED, $19D9, $AC99, $A829, $641F, $AD55,
    $13BB, $F76F, $B947, $2FEE, $B87B, $8930, $D37F, $7682);

  SD: array[0..127] of Word = (
    $1823, $C6E8, $87B8, $014F, $36A6, $D2F5, $796F, $9152,
    $60BC, $9B8E, $A30C, $7B35, $1DE0, $D7C2, $2E4B, $FE57,
    $1577, $37E5, $9FF0, $4ADA, $58C9, $290A, $B1A0, $6B85,
    $BD5D, $10F4, $CB3E, $0567, $E427, $418B, $A77D, $95D8,
    $FBEE, $7C66, $DD17, $479E, $CA2D, $BF07, $AD5A, $8333,
    $6302, $AA71, $C819, $49D9, $F2E3, $5B88, $9A26, $32B0,
    $E90F, $D580, $BECD, $3448, $FF7A, $905F, $2068, $1AAE,
    $B454, $9322, $64F1, $7312, $4008, $C3EC, $DBA1, $8D3D,
    $9700, $CF2B, $7682, $D61B, $B5AF, $6A50, $45F3, $30EF,
    $3F55, $A2EA, $65BA, $2FC0, $DE1C, $FD4D, $9275, $068A,
    $B2E6, $0E1F, $62D4, $A896, $F9C5, $2559, $8472, $394C,
    $5E78, $388C, $D1A5, $E261, $B321, $9C1E, $43C7, $FC04,
    $5199, $6D0D, $FADF, $7E24, $3BAB, $CE11, $8F4E, $B7EB,
    $3C81, $94F7, $B913, $2CD3, $E76E, $C403, $5644, $7FA9,
    $2ABB, $C153, $DC0B, $9D6C, $3174, $F646, $AC89, $14E1,
    $163A, $6909, $70B6, $D0ED, $CC42, $98A4, $285C, $F886);

{ THashWhirpoolAbstract }

class function THashWhirpoolAbstract.HashType: THashType;
begin
  Result := THashType.Cryptographic;
end;

function THashWhirpoolAbstract.BlockSize: Cardinal;
begin
  Result := 64;
end;

procedure THashWhirpoolAbstract.Initialize;
begin
  inherited;
  FState[0] := $0;
  FState[1] := $0;
  FState[2] := $0;
  FState[3] := $0;
  FState[4] := $0;
  FState[5] := $0;
  FState[6] := $0;
  FState[7] := $0;
  FLength := 0;
end;

procedure THashWhirpoolAbstract.Finalize;
begin
  inherited;
  ToBigEndian8(FState, FValue);
end;

function THashWhirpoolAbstract.GetPadBuffer: TBytes;
var
  i: Word;
  LengthInBits: UInt64;
  Len, n: Word;
begin
  Inc(FLength, UsedBuffer);

  LengthInBits := FLength shl 3;
  n := (FLength + 33) mod BlockSize;

  if n = 0 then
    Len := 33
  else
    Len := BlockSize - n + 33;

  SetLength(Result, Len);
  Result[0] := $80;
  for i := 1 to Len - 1 do
    Result[i] := 0;

  Dec(Len, 8);
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

{ THashWhirpool0 }

function THashWhirpool0.HashSize: Cardinal;
begin
  Result := 64;
end;

constructor THashWhirpool0.Create;
const
  Root = $11D;
var
  s, s2, s3, s4, s5, s8, s9, t: UInt64;
  SS: array[0..255] of Byte;
  i, r: Byte;
begin
  inherited;

  for i := 0 to 255 do
  begin
    if (i and 1) = 0 then
      s := (SD_0[i shr 1] shr 8) and $FF
    else
      s := SD_0[i shr 1] and $FF;
    s2 := s shl 1;
    if s2 > $FF then
      s2 := s2 xor Root;
    s3 := s2 xor s;
    s4 := s2 shl 1;
    if s4 > $FF then
      s4 := s4 xor Root;
    s5 := s4 xor s;
    s8 := s4 shl 1;
    if s8 > $FF then
      s8 := s8 xor Root;
    s9 := s8 xor s;

    SS[i] := Byte(s);
    t := (s  shl 56) or (s shl 48) or (s3 shl 40) or (s shl 32) or (s5 shl 24) or (s8 shl 16) or (s9 shl 8) or s5;
    FT0[i] := t;
    FT1[i] := (t shr  8) or (t shl 56);
    FT2[i] := (t shr 16) or (t shl 48);
    FT3[i] := (t shr 24) or (t shl 40);
    FT4[i] := (t shr 32) or (t shl 32);
    FT5[i] := (t shr 40) or (t shl 24);
    FT6[i] := (t shr 48) or (t shl 16);
    FT7[i] := (t shr 56) or (t shl 8);
  end;

  for r := 0 to High(FRC) do
    FRC[r] := SwapEndian(PUInt64(@SS[r shl 3])^);
end;

procedure THashWhirpool0.UpdateBlock(const Block: Pointer);
type
  PArray8UInt64 = ^TArray8UInt64;
  TArray8UInt64 = array[0..7] of UInt64;
var
//  A, B, C, D, E, F, G, H: UInt64;
  n0, n1, n2, n3, n4, n5, n6, n7: UInt64;
  k00, k01, k02, k03, k04, k05, k06, k07: UInt64;
  nn0, nn1, nn2, nn3, nn4, nn5, nn6, nn7: UInt64;
  kr0, kr1, kr2, kr3, kr4, kr5, kr6, kr7: UInt64;
  w0, w1, w2, w3, w4, w5, w6, w7: UInt64;
  r: Byte;
begin
  Inc(FLength, 64);

  n0 := SwapEndian(PArray8UInt64(Block)^[0]);
  n1 := SwapEndian(PArray8UInt64(Block)^[1]);
  n2 := SwapEndian(PArray8UInt64(Block)^[2]);
  n3 := SwapEndian(PArray8UInt64(Block)^[3]);
  n4 := SwapEndian(PArray8UInt64(Block)^[4]);
  n5 := SwapEndian(PArray8UInt64(Block)^[5]);
  n6 := SwapEndian(PArray8UInt64(Block)^[6]);
  n7 := SwapEndian(PArray8UInt64(Block)^[7]);

  k00 := FState[0];
  k01 := FState[1];
  k02 := FState[2];
  k03 := FState[3];
  k04 := FState[4];
  k05 := FState[5];
  k06 := FState[6];
  k07 := FState[7];

  nn0 := n0 xor k00;
  nn1 := n1 xor k01;
  nn2 := n2 xor k02;
  nn3 := n3 xor k03;
  nn4 := n4 xor k04;
  nn5 := n5 xor k05;
  nn6 := n6 xor k06;
  nn7 := n7 xor k07;

  for r := 0 to High(FRC) do
  begin
    kr0 := FT0[(k00 shr 56) and $FF] xor FT1[(k07 shr 48) and $FF] xor
          FT2[(k06 shr 40) and $FF] xor FT3[(k05 shr 32) and $FF] xor
          FT4[(k04 shr 24) and $FF] xor FT5[(k03 shr 16) and $FF] xor
          FT6[(k02 shr  8) and $FF] xor FT7[ k01 and $FF] xor FRC[r];

    kr1 := FT0[(k01 shr 56) and $FF] xor FT1[(k00 shr 48) and $FF] xor
          FT2[(k07 shr 40) and $FF] xor FT3[(k06 shr 32) and $FF] xor
          FT4[(k05 shr 24) and $FF] xor FT5[(k04 shr 16) and $FF] xor
          FT6[(k03 shr  8) and $FF] xor FT7[ k02 and $FF];

    kr2 := FT0[(k02 shr 56) and $FF] xor FT1[(k01 shr 48) and $FF] xor
          FT2[(k00 shr 40) and $FF] xor FT3[(k07 shr 32) and $FF] xor
          FT4[(k06 shr 24) and $FF] xor FT5[(k05 shr 16) and $FF] xor
          FT6[(k04 shr  8) and $FF] xor FT7[ k03 and $FF];

    kr3 := FT0[(k03 shr 56) and $FF] xor FT1[(k02 shr 48) and $FF] xor
          FT2[(k01 shr 40) and $FF] xor FT3[(k00 shr 32) and $FF] xor
          FT4[(k07 shr 24) and $FF] xor FT5[(k06 shr 16) and $FF] xor
          FT6[(k05 shr  8) and $FF] xor FT7[ k04 and $FF];

    kr4 := FT0[(k04 shr 56) and $FF] xor FT1[(k03 shr 48) and $FF] xor
          FT2[(k02 shr 40) and $FF] xor FT3[(k01 shr 32) and $FF] xor
          FT4[(k00 shr 24) and $FF] xor FT5[(k07 shr 16) and $FF] xor
          FT6[(k06 shr  8) and $FF] xor FT7[ k05 and $FF];

    kr5 := FT0[(k05 shr 56) and $FF] xor FT1[(k04 shr 48) and $FF] xor
          FT2[(k03 shr 40) and $FF] xor FT3[(k02 shr 32) and $FF] xor
          FT4[(k01 shr 24) and $FF] xor FT5[(k00 shr 16) and $FF] xor
          FT6[(k07 shr  8) and $FF] xor FT7[ k06 and $FF];

    kr6 := FT0[(k06 shr 56) and $FF] xor FT1[(k05 shr 48) and $FF] xor
          FT2[(k04 shr 40) and $FF] xor FT3[(k03 shr 32) and $FF] xor
          FT4[(k02 shr 24) and $FF] xor FT5[(k01 shr 16) and $FF] xor
          FT6[(k00 shr  8) and $FF] xor FT7[ k07 and $FF];

    kr7 := FT0[(k07 shr 56) and $FF] xor FT1[(k06 shr 48) and $FF] xor
          FT2[(k05 shr 40) and $FF] xor FT3[(k04 shr 32) and $FF] xor
          FT4[(k03 shr 24) and $FF] xor FT5[(k02 shr 16) and $FF] xor
          FT6[(k01 shr  8) and $FF] xor FT7[ k00 and $FF];

    k00 := kr0;
    k01 := kr1;
    k02 := kr2;
    k03 := kr3;
    k04 := kr4;
    k05 := kr5;
    k06 := kr6;
    k07 := kr7;

    w0 := FT0[(nn0 shr 56) and $FF] xor FT1[(nn7 shr 48) and $FF] xor
          FT2[(nn6 shr 40) and $FF] xor FT3[(nn5 shr 32) and $FF] xor
          FT4[(nn4 shr 24) and $FF] xor FT5[(nn3 shr 16) and $FF] xor
          FT6[(nn2 shr  8) and $FF] xor FT7[ nn1 and $FF] xor kr0;
    w1 := FT0[(nn1 shr 56) and $FF] xor FT1[(nn0 shr 48) and $FF] xor
          FT2[(nn7 shr 40) and $FF] xor FT3[(nn6 shr 32) and $FF] xor
          FT4[(nn5 shr 24) and $FF] xor FT5[(nn4 shr 16) and $FF] xor
          FT6[(nn3 shr  8) and $FF] xor FT7[ nn2 and $FF] xor kr1;
    w2 := FT0[(nn2 shr 56) and $FF] xor FT1[(nn1 shr 48) and $FF] xor
          FT2[(nn0 shr 40) and $FF] xor FT3[(nn7 shr 32) and $FF] xor
          FT4[(nn6 shr 24) and $FF] xor FT5[(nn5 shr 16) and $FF] xor
          FT6[(nn4 shr  8) and $FF] xor FT7[ nn3 and $FF] xor kr2;
    w3 := FT0[(nn3 shr 56) and $FF] xor FT1[(nn2 shr 48) and $FF] xor
          FT2[(nn1 shr 40) and $FF] xor FT3[(nn0 shr 32) and $FF] xor
          FT4[(nn7 shr 24) and $FF] xor FT5[(nn6 shr 16) and $FF] xor
          FT6[(nn5 shr  8) and $FF] xor FT7[ nn4 and $FF] xor kr3;
    w4 := FT0[(nn4 shr 56) and $FF] xor FT1[(nn3 shr 48) and $FF] xor
          FT2[(nn2 shr 40) and $FF] xor FT3[(nn1 shr 32) and $FF] xor
          FT4[(nn0 shr 24) and $FF] xor FT5[(nn7 shr 16) and $FF] xor
          FT6[(nn6 shr  8) and $FF] xor FT7[ nn5 and $FF] xor kr4;
    w5 := FT0[(nn5 shr 56) and $FF] xor FT1[(nn4 shr 48) and $FF] xor
          FT2[(nn3 shr 40) and $FF] xor FT3[(nn2 shr 32) and $FF] xor
          FT4[(nn1 shr 24) and $FF] xor FT5[(nn0 shr 16) and $FF] xor
          FT6[(nn7 shr  8) and $FF] xor FT7[ nn6 and $FF] xor kr5;
    w6 := FT0[(nn6 shr 56) and $FF] xor FT1[(nn5 shr 48) and $FF] xor
          FT2[(nn4 shr 40) and $FF] xor FT3[(nn3 shr 32) and $FF] xor
          FT4[(nn2 shr 24) and $FF] xor FT5[(nn1 shr 16) and $FF] xor
          FT6[(nn0 shr  8) and $FF] xor FT7[ nn7 and $FF] xor kr6;
    w7 := FT0[(nn7 shr 56) and $FF] xor FT1[(nn6 shr 48) and $FF] xor
          FT2[(nn5 shr 40) and $FF] xor FT3[(nn4 shr 32) and $FF] xor
          FT4[(nn3 shr 24) and $FF] xor FT5[(nn2 shr 16) and $FF] xor
          FT6[(nn1 shr  8) and $FF] xor FT7[ nn0 and $FF] xor kr7;

    nn0 := w0;
    nn1 := w1;
    nn2 := w2;
    nn3 := w3;
    nn4 := w4;
    nn5 := w5;
    nn6 := w6;
    nn7 := w7;
  end;

  FState[0] := FState[0] xor (w0 xor n0);
  FState[1] := FState[1] xor (w1 xor n1);
  FState[2] := FState[2] xor (w2 xor n2);
  FState[3] := FState[3] xor (w3 xor n3);
  FState[4] := FState[4] xor (w4 xor n4);
  FState[5] := FState[5] xor (w5 xor n5);
  FState[6] := FState[6] xor (w6 xor n6);
  FState[7] := FState[7] xor (w7 xor n7);
end;

{ THashWhirpool }

function THashWhirpool.HashSize: Cardinal;
begin
  Result := 64;
end;

constructor THashWhirpool.Create(const AModificationType: THashWhirpoolModification);
const
  Root = $11D;
var
  s, s2, s3, s4, s5, s8, s9, t: UInt64;
  SS: array[0..255] of Byte;
  i, r: Byte;
begin
  inherited Create;

  FModificationType := AModificationType;
  for i := 0 to 255 do
  begin
    if (i and 1) = 0 then
      s := (SD[i shr 1] shr 8) and $FF
    else
      s := SD[i shr 1] and $FF;
    s2 := s shl 1;
    if s2 > $FF then
      s2 := s2 xor Root;
    s3 := s2 xor s;
    s4 := s2 shl 1;
    if s4 > $FF then
      s4 := s4 xor Root;
    s5 := s4 xor s;
    s8 := s4 shl 1;
    if s8 > $FF then
      s8 := s8 xor Root;
    s9 := s8 xor s;

    SS[i] := Byte(s);
    case FModificationType of
      THashWhirpoolModification.Whirpool1:
        t := (s  shl 56) or (s shl 48) or (s3 shl 40) or (s shl 32) or (s5 shl 24) or (s8 shl 16) or (s9 shl 8) or s5;
      THashWhirpoolModification.Whirpool2:
        t := (s  shl 56) or (s shl 48) or (s4 shl 40) or (s shl 32) or (s8 shl 24) or (s5 shl 16) or (s2 shl 8) or s9;
      else t := 0; // reduce warning
    end;

    FT0[i] := t;
    FT1[i] := (t shr  8) or (t shl 56);
    FT2[i] := (t shr 16) or (t shl 48);
    FT3[i] := (t shr 24) or (t shl 40);
    FT4[i] := (t shr 32) or (t shl 32);
    FT5[i] := (t shr 40) or (t shl 24);
    FT6[i] := (t shr 48) or (t shl 16);
    FT7[i] := (t shr 56) or (t shl 8);
  end;

  for r := 0 to High(FRC) do
    FRC[r] := SwapEndian(PUInt64(@SS[r shl 3])^);
end;

procedure THashWhirpool.UpdateBlock(const Block: Pointer);
type
  PArray8UInt64 = ^TArray8UInt64;
  TArray8UInt64 = array[0..7] of UInt64;
var
//  A, B, C, D, E, F, G, H: UInt64;
  n0, n1, n2, n3, n4, n5, n6, n7: UInt64;
  k00, k01, k02, k03, k04, k05, k06, k07: UInt64;
  nn0, nn1, nn2, nn3, nn4, nn5, nn6, nn7: UInt64;
  kr0, kr1, kr2, kr3, kr4, kr5, kr6, kr7: UInt64;
  w0, w1, w2, w3, w4, w5, w6, w7: UInt64;
  r: Byte;
begin
  Inc(FLength, 64);

  n0 := SwapEndian(PArray8UInt64(Block)^[0]);
  n1 := SwapEndian(PArray8UInt64(Block)^[1]);
  n2 := SwapEndian(PArray8UInt64(Block)^[2]);
  n3 := SwapEndian(PArray8UInt64(Block)^[3]);
  n4 := SwapEndian(PArray8UInt64(Block)^[4]);
  n5 := SwapEndian(PArray8UInt64(Block)^[5]);
  n6 := SwapEndian(PArray8UInt64(Block)^[6]);
  n7 := SwapEndian(PArray8UInt64(Block)^[7]);

  k00 := FState[0];
  k01 := FState[1];
  k02 := FState[2];
  k03 := FState[3];
  k04 := FState[4];
  k05 := FState[5];
  k06 := FState[6];
  k07 := FState[7];

  nn0 := n0 xor k00;
  nn1 := n1 xor k01;
  nn2 := n2 xor k02;
  nn3 := n3 xor k03;
  nn4 := n4 xor k04;
  nn5 := n5 xor k05;
  nn6 := n6 xor k06;
  nn7 := n7 xor k07;

  for r := 0 to High(FRC) do
  begin
    kr0 := FT0[(k00 shr 56) and $FF] xor FT1[(k07 shr 48) and $FF] xor
          FT2[(k06 shr 40) and $FF] xor FT3[(k05 shr 32) and $FF] xor
          FT4[(k04 shr 24) and $FF] xor FT5[(k03 shr 16) and $FF] xor
          FT6[(k02 shr  8) and $FF] xor FT7[ k01 and $FF] xor FRC[r];

    kr1 := FT0[(k01 shr 56) and $FF] xor FT1[(k00 shr 48) and $FF] xor
          FT2[(k07 shr 40) and $FF] xor FT3[(k06 shr 32) and $FF] xor
          FT4[(k05 shr 24) and $FF] xor FT5[(k04 shr 16) and $FF] xor
          FT6[(k03 shr  8) and $FF] xor FT7[ k02 and $FF];

    kr2 := FT0[(k02 shr 56) and $FF] xor FT1[(k01 shr 48) and $FF] xor
          FT2[(k00 shr 40) and $FF] xor FT3[(k07 shr 32) and $FF] xor
          FT4[(k06 shr 24) and $FF] xor FT5[(k05 shr 16) and $FF] xor
          FT6[(k04 shr  8) and $FF] xor FT7[ k03 and $FF];

    kr3 := FT0[(k03 shr 56) and $FF] xor FT1[(k02 shr 48) and $FF] xor
          FT2[(k01 shr 40) and $FF] xor FT3[(k00 shr 32) and $FF] xor
          FT4[(k07 shr 24) and $FF] xor FT5[(k06 shr 16) and $FF] xor
          FT6[(k05 shr  8) and $FF] xor FT7[ k04 and $FF];

    kr4 := FT0[(k04 shr 56) and $FF] xor FT1[(k03 shr 48) and $FF] xor
          FT2[(k02 shr 40) and $FF] xor FT3[(k01 shr 32) and $FF] xor
          FT4[(k00 shr 24) and $FF] xor FT5[(k07 shr 16) and $FF] xor
          FT6[(k06 shr  8) and $FF] xor FT7[ k05 and $FF];

    kr5 := FT0[(k05 shr 56) and $FF] xor FT1[(k04 shr 48) and $FF] xor
          FT2[(k03 shr 40) and $FF] xor FT3[(k02 shr 32) and $FF] xor
          FT4[(k01 shr 24) and $FF] xor FT5[(k00 shr 16) and $FF] xor
          FT6[(k07 shr  8) and $FF] xor FT7[ k06 and $FF];

    kr6 := FT0[(k06 shr 56) and $FF] xor FT1[(k05 shr 48) and $FF] xor
          FT2[(k04 shr 40) and $FF] xor FT3[(k03 shr 32) and $FF] xor
          FT4[(k02 shr 24) and $FF] xor FT5[(k01 shr 16) and $FF] xor
          FT6[(k00 shr  8) and $FF] xor FT7[ k07 and $FF];

    kr7 := FT0[(k07 shr 56) and $FF] xor FT1[(k06 shr 48) and $FF] xor
          FT2[(k05 shr 40) and $FF] xor FT3[(k04 shr 32) and $FF] xor
          FT4[(k03 shr 24) and $FF] xor FT5[(k02 shr 16) and $FF] xor
          FT6[(k01 shr  8) and $FF] xor FT7[ k00 and $FF];

    k00 := kr0;
    k01 := kr1;
    k02 := kr2;
    k03 := kr3;
    k04 := kr4;
    k05 := kr5;
    k06 := kr6;
    k07 := kr7;

    w0 := FT0[(nn0 shr 56) and $FF] xor FT1[(nn7 shr 48) and $FF] xor
          FT2[(nn6 shr 40) and $FF] xor FT3[(nn5 shr 32) and $FF] xor
          FT4[(nn4 shr 24) and $FF] xor FT5[(nn3 shr 16) and $FF] xor
          FT6[(nn2 shr  8) and $FF] xor FT7[ nn1 and $FF] xor kr0;
    w1 := FT0[(nn1 shr 56) and $FF] xor FT1[(nn0 shr 48) and $FF] xor
          FT2[(nn7 shr 40) and $FF] xor FT3[(nn6 shr 32) and $FF] xor
          FT4[(nn5 shr 24) and $FF] xor FT5[(nn4 shr 16) and $FF] xor
          FT6[(nn3 shr  8) and $FF] xor FT7[ nn2 and $FF] xor kr1;
    w2 := FT0[(nn2 shr 56) and $FF] xor FT1[(nn1 shr 48) and $FF] xor
          FT2[(nn0 shr 40) and $FF] xor FT3[(nn7 shr 32) and $FF] xor
          FT4[(nn6 shr 24) and $FF] xor FT5[(nn5 shr 16) and $FF] xor
          FT6[(nn4 shr  8) and $FF] xor FT7[ nn3 and $FF] xor kr2;
    w3 := FT0[(nn3 shr 56) and $FF] xor FT1[(nn2 shr 48) and $FF] xor
          FT2[(nn1 shr 40) and $FF] xor FT3[(nn0 shr 32) and $FF] xor
          FT4[(nn7 shr 24) and $FF] xor FT5[(nn6 shr 16) and $FF] xor
          FT6[(nn5 shr  8) and $FF] xor FT7[ nn4 and $FF] xor kr3;
    w4 := FT0[(nn4 shr 56) and $FF] xor FT1[(nn3 shr 48) and $FF] xor
          FT2[(nn2 shr 40) and $FF] xor FT3[(nn1 shr 32) and $FF] xor
          FT4[(nn0 shr 24) and $FF] xor FT5[(nn7 shr 16) and $FF] xor
          FT6[(nn6 shr  8) and $FF] xor FT7[ nn5 and $FF] xor kr4;
    w5 := FT0[(nn5 shr 56) and $FF] xor FT1[(nn4 shr 48) and $FF] xor
          FT2[(nn3 shr 40) and $FF] xor FT3[(nn2 shr 32) and $FF] xor
          FT4[(nn1 shr 24) and $FF] xor FT5[(nn0 shr 16) and $FF] xor
          FT6[(nn7 shr  8) and $FF] xor FT7[ nn6 and $FF] xor kr5;
    w6 := FT0[(nn6 shr 56) and $FF] xor FT1[(nn5 shr 48) and $FF] xor
          FT2[(nn4 shr 40) and $FF] xor FT3[(nn3 shr 32) and $FF] xor
          FT4[(nn2 shr 24) and $FF] xor FT5[(nn1 shr 16) and $FF] xor
          FT6[(nn0 shr  8) and $FF] xor FT7[ nn7 and $FF] xor kr6;
    w7 := FT0[(nn7 shr 56) and $FF] xor FT1[(nn6 shr 48) and $FF] xor
          FT2[(nn5 shr 40) and $FF] xor FT3[(nn4 shr 32) and $FF] xor
          FT4[(nn3 shr 24) and $FF] xor FT5[(nn2 shr 16) and $FF] xor
          FT6[(nn1 shr  8) and $FF] xor FT7[ nn0 and $FF] xor kr7;

    nn0 := w0;
    nn1 := w1;
    nn2 := w2;
    nn3 := w3;
    nn4 := w4;
    nn5 := w5;
    nn6 := w6;
    nn7 := w7;
  end;

  FState[0] := FState[0] xor (w0 xor n0);
  FState[1] := FState[1] xor (w1 xor n1);
  FState[2] := FState[2] xor (w2 xor n2);
  FState[3] := FState[3] xor (w3 xor n3);
  FState[4] := FState[4] xor (w4 xor n4);
  FState[5] := FState[5] xor (w5 xor n5);
  FState[6] := FState[6] xor (w6 xor n6);
  FState[7] := FState[7] xor (w7 xor n7);
end;

end.
