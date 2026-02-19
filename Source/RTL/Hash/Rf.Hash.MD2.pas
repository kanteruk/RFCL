{ *********************************************************************** }
{ Copyright (c) 2010-2011 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.Hash.MD2;

interface

uses Rf.Types, Rf.SysUtils, Rf.Hash;

type

  /// <summary>
  /// Message-Digest 2 (MD2)
  /// </summary>
  THashMD2 = class(TBlockHash)
  private
    FState: array[0..3] of Cardinal;
    FChecksum: array[0..15] of Byte;
  protected
    procedure Initialize; override;
    procedure UpdateBlock(const BlockBuf: Pointer); override;
    function GetPadBuffer: TBytes; override;
    procedure Finalize; override;
  public
    class function HashType: THashType; override;
    function HashSize: Cardinal; override;
    function BlockSize: Cardinal; override;
  end;

implementation

{ THashMD2 }

class function THashMD2.HashType: THashType;
begin
  Result := THashType.Cryptographic;
end;

function THashMD2.HashSize: Cardinal;
begin
  Result := 16;
end;

function THashMD2.BlockSize: Cardinal;
begin
  Result := 16;
end;

procedure THashMD2.Initialize;
begin
  inherited;
  FState[0] := 0;
  FState[1] := 0;
  FState[2] := 0;
  FState[3] := 0;
  FillChar(FChecksum, SizeOf(FChecksum), 0);
end;

procedure THashMD2.UpdateBlock(const BlockBuf: Pointer);
const
  PI_SUBST: array[Byte] of Byte = (
    41,  46,  67, 201, 162, 216, 124,   1,  61,  54,  84, 161, 236, 240,   6,  19,
    98, 167,   5, 243, 192, 199, 115, 140, 152, 147,  43, 217, 188,  76, 130, 202,
    30, 155,  87,  60, 253, 212, 224,  22, 103,  66, 111,  24, 138,  23, 229,  18,
   190,  78, 196, 214, 218, 158, 222,  73, 160, 251, 245, 142, 187,  47, 238, 122,
   169, 104, 121, 145,  21, 178,   7,  63, 148, 194,  16, 137,  11,  34,  95,  33,
   128, 127,  93, 154,  90, 144,  50,  39,  53,  62, 204, 231, 191, 247, 151,   3,
   255,  25,  48, 179,  72, 165, 181, 209, 215,  94, 146,  42, 172,  86, 170, 198,
    79, 184,  56, 210, 150, 164, 125, 182, 118, 252, 107, 226, 156, 116,   4, 241,
    69, 157, 112,  89, 100, 113, 135,  32, 134,  91, 207, 101, 230,  45, 168,   2,
    27,  96,  37, 173, 174, 176, 185, 246,  28,  70,  97, 105,  52,  64, 126,  15,
    85,  71, 163,  35, 221,  81, 175,  58, 195,  92, 249, 206, 186, 197, 234,  38,
    44,  83,  13, 110, 133,  40, 132,   9, 211, 223, 205, 244,  65, 129,  77,  82,
   106, 220,  55, 200, 108, 193, 171, 250,  36, 225, 123,   8,  12, 189, 177,  74,
   120, 136, 149, 139, 227,  99, 232, 109, 233, 203, 213, 254,  59,   0,  29,  57,
   242, 239, 183,  14, 102,  88, 208, 228, 166, 119, 114, 248, 235, 117,  75,  10,
    49,  68,  80, 180, 143, 237,  31,  26, 219, 153, 141,  51, 159,  17, 131,  20);
type
  PArray16Byte = ^TArray16Byte;
  TArray16Byte = array[0..15] of Byte;
var
  Block: PArray16Byte;
  x: array[0..31] of Byte;
  PState: PArray16Byte;
  i, j: Integer;
  t: Byte;
begin
  Block := BlockBuf;

  PState := @FState;
  Move(Block^, x, 16);
  for i := 0 to 15 do
    x[i + 16] := PState^[i] xor Block^[i];

  { Encrypt block (18 rounds) }
  t := 0;
  for i := 0 to 17 do
  begin
    for j := 0 to 15 do
    begin
      PState^[j] := PState^[j] xor PI_SUBST[t];
      t := PState^[j];
    end;
    for j := 0 to 31 do
    begin
      x[j] := x[j] xor PI_SUBST[t];
      t := x[j];
    end;
    t := (t + i) and $FF;
  end;

  { Update checksum }
  t := FChecksum[15];
  for i := 0 to 15  do
  begin
    t := FChecksum[i] xor PI_SUBST[Block^[i] xor t];
    FChecksum[i] := t;
  end;
end;

function THashMD2.GetPadBuffer: TBytes;
var
  i, PadLen: Word;
begin
  PadLen := BlockSize - FUsedBuffer;
  SetLength(Result, PadLen);
  for i := 0 to PadLen - 1 do
    Result[i] := PadLen;
end;

procedure THashMD2.Finalize;
begin
  inherited;
  UpdateBlock(@FChecksum[0]);

  SetValueFromBuffer(@FState, HashSize);
end;

end.
