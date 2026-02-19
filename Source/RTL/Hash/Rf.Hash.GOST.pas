{ *********************************************************************** }
{ Copyright (c) 2010-2019 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.Hash.GOST;

interface

uses Rf.Types, Rf.SysUtils, Rf.Hash;

type

  /// <summary>
  /// GOST R 34.11-94 Hash Algorithm 256Bit (GOST)
  /// </summary>
  THashGOST = class(TBlockHash)
  private
    FState: array[0..7] of Cardinal;
    FSum: array[0..7] of Cardinal;
    FLength: UInt64;
  protected
    procedure Initialize; override;
    procedure Compress(const Block: Pointer);
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
  SBox1: array[Byte] of Cardinal = (
    $72000, $75000, $74800, $71000, $76800, $74000, $70000, $77000,
    $73000, $75800, $70800, $76000, $73800, $77800, $72800, $71800,
    $5A000, $5D000, $5C800, $59000, $5E800, $5C000, $58000, $5F000,
    $5B000, $5D800, $58800, $5E000, $5B800, $5F800, $5A800, $59800,
    $22000, $25000, $24800, $21000, $26800, $24000, $20000, $27000,
    $23000, $25800, $20800, $26000, $23800, $27800, $22800, $21800,
    $62000, $65000, $64800, $61000, $66800, $64000, $60000, $67000,
    $63000, $65800, $60800, $66000, $63800, $67800, $62800, $61800,
    $32000, $35000, $34800, $31000, $36800, $34000, $30000, $37000,
    $33000, $35800, $30800, $36000, $33800, $37800, $32800, $31800,
    $6A000, $6D000, $6C800, $69000, $6E800, $6C000, $68000, $6F000,
    $6B000, $6D800, $68800, $6E000, $6B800, $6F800, $6A800, $69800,
    $7A000, $7D000, $7C800, $79000, $7E800, $7C000, $78000, $7F000,
    $7B000, $7D800, $78800, $7E000, $7B800, $7F800, $7A800, $79800,
    $52000, $55000, $54800, $51000, $56800, $54000, $50000, $57000,
    $53000, $55800, $50800, $56000, $53800, $57800, $52800, $51800,
    $12000, $15000, $14800, $11000, $16800, $14000, $10000, $17000,
    $13000, $15800, $10800, $16000, $13800, $17800, $12800, $11800,
    $1A000, $1D000, $1C800, $19000, $1E800, $1C000, $18000, $1F000,
    $1B000, $1D800, $18800, $1E000, $1B800, $1F800, $1A800, $19800,
    $42000, $45000, $44800, $41000, $46800, $44000, $40000, $47000,
    $43000, $45800, $40800, $46000, $43800, $47800, $42800, $41800,
    $0A000, $0D000, $0C800, $09000, $0E800, $0C000, $08000, $0F000,
    $0B000, $0D800, $08800, $0E000, $0B800, $0F800, $0A800, $09800,
    $02000, $05000, $04800, $01000, $06800, $04000, $00000, $07000,
    $03000, $05800, $00800, $06000, $03800, $07800, $02800, $01800,
    $3A000, $3D000, $3C800, $39000, $3E800, $3C000, $38000, $3F000,
    $3B000, $3D800, $38800, $3E000, $3B800, $3F800, $3A800, $39800,
    $2A000, $2D000, $2C800, $29000, $2E800, $2C000, $28000, $2F000,
    $2B000, $2D800, $28800, $2E000, $2B800, $2F800, $2A800, $29800,
    $4A000, $4D000, $4C800, $49000, $4E800, $4C000, $48000, $4F000,
    $4B000, $4D800, $48800, $4E000, $4B800, $4F800, $4A800, $49800);

  SBox2: array[Byte] of Cardinal = (
    $3A80000, $3C00000, $3880000, $3E80000, $3D00000, $3980000, $3A00000, $3900000,
    $3F00000, $3F80000, $3E00000, $3B80000, $3B00000, $3800000, $3C80000, $3D80000,
    $6A80000, $6C00000, $6880000, $6E80000, $6D00000, $6980000, $6A00000, $6900000,
    $6F00000, $6F80000, $6E00000, $6B80000, $6B00000, $6800000, $6C80000, $6D80000,
    $5280000, $5400000, $5080000, $5680000, $5500000, $5180000, $5200000, $5100000,
    $5700000, $5780000, $5600000, $5380000, $5300000, $5000000, $5480000, $5580000,
    $0A80000, $0C00000, $0880000, $0E80000, $0D00000, $0980000, $0A00000, $0900000,
    $0F00000, $0F80000, $0E00000, $0B80000, $0B00000, $0800000, $0C80000, $0D80000,
    $0280000, $0400000, $0080000, $0680000, $0500000, $0180000, $0200000, $0100000,
    $0700000, $0780000, $0600000, $0380000, $0300000, $0000000, $0480000, $0580000,
    $4280000, $4400000, $4080000, $4680000, $4500000, $4180000, $4200000, $4100000,
    $4700000, $4780000, $4600000, $4380000, $4300000, $4000000, $4480000, $4580000,
    $4A80000, $4C00000, $4880000, $4E80000, $4D00000, $4980000, $4A00000, $4900000,
    $4F00000, $4F80000, $4E00000, $4B80000, $4B00000, $4800000, $4C80000, $4D80000,
    $7A80000, $7C00000, $7880000, $7E80000, $7D00000, $7980000, $7A00000, $7900000,
    $7F00000, $7F80000, $7E00000, $7B80000, $7B00000, $7800000, $7C80000, $7D80000,
    $7280000, $7400000, $7080000, $7680000, $7500000, $7180000, $7200000, $7100000,
    $7700000, $7780000, $7600000, $7380000, $7300000, $7000000, $7480000, $7580000,
    $2280000, $2400000, $2080000, $2680000, $2500000, $2180000, $2200000, $2100000,
    $2700000, $2780000, $2600000, $2380000, $2300000, $2000000, $2480000, $2580000,
    $3280000, $3400000, $3080000, $3680000, $3500000, $3180000, $3200000, $3100000,
    $3700000, $3780000, $3600000, $3380000, $3300000, $3000000, $3480000, $3580000,
    $6280000, $6400000, $6080000, $6680000, $6500000, $6180000, $6200000, $6100000,
    $6700000, $6780000, $6600000, $6380000, $6300000, $6000000, $6480000, $6580000,
    $5A80000, $5C00000, $5880000, $5E80000, $5D00000, $5980000, $5A00000, $5900000,
    $5F00000, $5F80000, $5E00000, $5B80000, $5B00000, $5800000, $5C80000, $5D80000,
    $1280000, $1400000, $1080000, $1680000, $1500000, $1180000, $1200000, $1100000,
    $1700000, $1780000, $1600000, $1380000, $1300000, $1000000, $1480000, $1580000,
    $2A80000, $2C00000, $2880000, $2E80000, $2D00000, $2980000, $2A00000, $2900000,
    $2F00000, $2F80000, $2E00000, $2B80000, $2B00000, $2800000, $2C80000, $2D80000,
    $1A80000, $1C00000, $1880000, $1E80000, $1D00000, $1980000, $1A00000, $1900000,
    $1F00000, $1F80000, $1E00000, $1B80000, $1B00000, $1800000, $1C80000, $1D80000);

  SBox3: array[Byte] of Cardinal = (
    $30000002, $60000002, $38000002, $08000002, $28000002, $78000002, $68000002, $40000002,
    $20000002, $50000002, $48000002, $70000002, $00000002, $18000002, $58000002, $10000002,
    $B0000005, $E0000005, $B8000005, $88000005, $A8000005, $F8000005, $E8000005, $C0000005,
    $A0000005, $D0000005, $C8000005, $F0000005, $80000005, $98000005, $D8000005, $90000005,
    $30000005, $60000005, $38000005, $08000005, $28000005, $78000005, $68000005, $40000005,
    $20000005, $50000005, $48000005, $70000005, $00000005, $18000005, $58000005, $10000005,
    $30000000, $60000000, $38000000, $08000000, $28000000, $78000000, $68000000, $40000000,
    $20000000, $50000000, $48000000, $70000000, $00000000, $18000000, $58000000, $10000000,
    $B0000003, $E0000003, $B8000003, $88000003, $A8000003, $F8000003, $E8000003, $C0000003,
    $A0000003, $D0000003, $C8000003, $F0000003, $80000003, $98000003, $D8000003, $90000003,
    $30000001, $60000001, $38000001, $08000001, $28000001, $78000001, $68000001, $40000001,
    $20000001, $50000001, $48000001, $70000001, $00000001, $18000001, $58000001, $10000001,
    $B0000000, $E0000000, $B8000000, $88000000, $A8000000, $F8000000, $E8000000, $C0000000,
    $A0000000, $D0000000, $C8000000, $F0000000, $80000000, $98000000, $D8000000, $90000000,
    $B0000006, $E0000006, $B8000006, $88000006, $A8000006, $F8000006, $E8000006, $C0000006,
    $A0000006, $D0000006, $C8000006, $F0000006, $80000006, $98000006, $D8000006, $90000006,
    $B0000001, $E0000001, $B8000001, $88000001, $A8000001, $F8000001, $E8000001, $C0000001,
    $A0000001, $D0000001, $C8000001, $F0000001, $80000001, $98000001, $D8000001, $90000001,
    $30000003, $60000003, $38000003, $08000003, $28000003, $78000003, $68000003, $40000003,
    $20000003, $50000003, $48000003, $70000003, $00000003, $18000003, $58000003, $10000003,
    $30000004, $60000004, $38000004, $08000004, $28000004, $78000004, $68000004, $40000004,
    $20000004, $50000004, $48000004, $70000004, $00000004, $18000004, $58000004, $10000004,
    $B0000002, $E0000002, $B8000002, $88000002, $A8000002, $F8000002, $E8000002, $C0000002,
    $A0000002, $D0000002, $C8000002, $F0000002, $80000002, $98000002, $D8000002, $90000002,
    $B0000004, $E0000004, $B8000004, $88000004, $A8000004, $F8000004, $E8000004, $C0000004,
    $A0000004, $D0000004, $C8000004, $F0000004, $80000004, $98000004, $D8000004, $90000004,
    $30000006, $60000006, $38000006, $08000006, $28000006, $78000006, $68000006, $40000006,
    $20000006, $50000006, $48000006, $70000006, $00000006, $18000006, $58000006, $10000006,
    $B0000007, $E0000007, $B8000007, $88000007, $A8000007, $F8000007, $E8000007, $C0000007,
    $A0000007, $D0000007, $C8000007, $F0000007, $80000007, $98000007, $D8000007, $90000007,
    $30000007, $60000007, $38000007, $08000007, $28000007, $78000007, $68000007, $40000007,
    $20000007, $50000007, $48000007, $70000007, $00000007, $18000007, $58000007, $10000007);

  SBox4: array[Byte] of Cardinal = (
    $0E8, $0D8, $0A0, $088, $098, $0F8, $0A8, $0C8, $080, $0D0, $0F0, $0B8, $0B0, $0C0, $090, $0E0,
    $7E8, $7D8, $7A0, $788, $798, $7F8, $7A8, $7C8, $780, $7D0, $7F0, $7B8, $7B0, $7C0, $790, $7E0,
    $6E8, $6D8, $6A0, $688, $698, $6F8, $6A8, $6C8, $680, $6D0, $6F0, $6B8, $6B0, $6C0, $690, $6E0,
    $068, $058, $020, $008, $018, $078, $028, $048, $000, $050, $070, $038, $030, $040, $010, $060,
    $2E8, $2D8, $2A0, $288, $298, $2F8, $2A8, $2C8, $280, $2D0, $2F0, $2B8, $2B0, $2C0, $290, $2E0,
    $3E8, $3D8, $3A0, $388, $398, $3F8, $3A8, $3C8, $380, $3D0, $3F0, $3B8, $3B0, $3C0, $390, $3E0,
    $568, $558, $520, $508, $518, $578, $528, $548, $500, $550, $570, $538, $530, $540, $510, $560,
    $268, $258, $220, $208, $218, $278, $228, $248, $200, $250, $270, $238, $230, $240, $210, $260,
    $4E8, $4D8, $4A0, $488, $498, $4F8, $4A8, $4C8, $480, $4D0, $4F0, $4B8, $4B0, $4C0, $490, $4E0,
    $168, $158, $120, $108, $118, $178, $128, $148, $100, $150, $170, $138, $130, $140, $110, $160,
    $1E8, $1D8, $1A0, $188, $198, $1F8, $1A8, $1C8, $180, $1D0, $1F0, $1B8, $1B0, $1C0, $190, $1E0,
    $768, $758, $720, $708, $718, $778, $728, $748, $700, $750, $770, $738, $730, $740, $710, $760,
    $368, $358, $320, $308, $318, $378, $328, $348, $300, $350, $370, $338, $330, $340, $310, $360,
    $5E8, $5D8, $5A0, $588, $598, $5F8, $5A8, $5C8, $580, $5D0, $5F0, $5B8, $5B0, $5C0, $590, $5E0,
    $468, $458, $420, $408, $418, $478, $428, $448, $400, $450, $470, $438, $430, $440, $410, $460,
    $668, $658, $620, $608, $618, $678, $628, $648, $600, $650, $670, $638, $630, $640, $610, $660);

{ THashGOST }

class function THashGOST.HashType: THashType;
begin
  Result := THashType.Cryptographic;
end;

function THashGOST.HashSize: Cardinal;
begin
  Result := 32;
end;

function THashGOST.BlockSize: Cardinal;
begin
  Result := 32;
end;

procedure THashGOST.Initialize;
begin
  inherited;
  FillChar(FState, SizeOf(FState), 0);
  FillChar(FSum, SizeOf(FSum), 0);
  FLength := 0;
end;

type
  PArray8Cardinal = ^TArray8Cardinal;
  TArray8Cardinal = array[0..7] of Cardinal;

procedure GOSTEncryptRound(var l, r: Cardinal; const k1, k2: Cardinal); inline;
var
  t: Cardinal;
begin
  t := k1 + r;
  l := l xor (SBox1[t and $FF] xor SBox2[(t shr 8) and $FF] xor
    SBox3[(t shr 16) and $FF] xor SBox4[t shr 24]);
  t := k2 + l;
  r := r xor (SBox1[t and $FF] xor SBox2[(t shr 8) and $FF] xor
    SBox3[(t shr 16) and $FF] xor SBox4[t shr 24]);
end;

procedure THashGOST.Compress(const Block: Pointer);
var
  A, B, C, D, E, F, G, H: Cardinal;
  i, L, R: Cardinal;
  Key, v, w, s: TArray8Cardinal;
begin
  A := FState[0];
  B := FState[1];
  C := FState[2];
  D := FState[3];
  E := FState[4];
  F := FState[5];
  G := FState[6];
  H := FState[7];
  Move(Block^, v, SizeOf(v));
  i := 0;
  while i < 8 do
  begin
    w[0] := A xor v[0];
    w[1] := B xor v[1];
    w[2] := C xor v[2];
    w[3] := D xor v[3];
    w[4] := E xor v[4];
    w[5] := F xor v[5];
    w[6] := G xor v[6];
    w[7] := H xor v[7];

    {P-Transformation}

    Key[0] := (w[0] and $000000ff) or ((w[2] and $000000ff) shl 8) or ((w[4] and $000000ff) shl 16)
      or ((w[6] and $000000ff) shl 24);
    Key[1] := ((w[0] and $0000ff00) shr 8) or (w[2] and $0000ff00) or ((w[4] and $0000ff00) shl 8)
      or ((w[6] and $0000ff00) shl 16);
    Key[2] := ((w[0] and $00ff0000) shr 16) or ((w[2] and $00ff0000) shr 8) or (w[4] and $00ff0000)
      or ((w[6] and $00ff0000) shl 8);
    Key[3] := ((w[0] and $ff000000) shr 24) or ((w[2] and $ff000000) shr 16) or
      ((w[4] and $ff000000) shr 8) or (w[6] and $ff000000);
    Key[4] := (w[1] and $000000ff) or ((w[3] and $000000ff) shl 8) or ((w[5] and $000000ff) shl 16)
      or ((w[7] and $000000ff) shl 24);
    Key[5] := ((w[1] and $0000ff00) shr 8) or (w[3] and $0000ff00) or ((w[5] and $0000ff00) shl 8)
      or ((w[7] and $0000ff00) shl 16);
    Key[6] := ((w[1] and $00ff0000) shr 16) or ((w[3] and $00ff0000) shr 8) or (w[5] and $00ff0000)
      or ((w[7] and $00ff0000) shl 8);
    Key[7] := ((w[1] and $ff000000) shr 24) or ((w[3] and $ff000000) shr 16) or
      ((w[5] and $ff000000) shr 8) or (w[7] and $ff000000);


    R := FState[i];
    L := FState[i + 1];
    { Gost Encrypt }
    GOSTEncryptRound(L, R, Key[0], Key[1]);
    GOSTEncryptRound(L, R, Key[2], Key[3]);
    GOSTEncryptRound(L, R, Key[4], Key[5]);
    GOSTEncryptRound(L, R, Key[6], Key[7]);
    GOSTEncryptRound(L, R, Key[0], Key[1]);
    GOSTEncryptRound(L, R, Key[2], Key[3]);
    GOSTEncryptRound(L, R, Key[4], Key[5]);
    GOSTEncryptRound(L, R, Key[6], Key[7]);
    GOSTEncryptRound(L, R, Key[0], Key[1]);
    GOSTEncryptRound(L, R, Key[2], Key[3]);
    GOSTEncryptRound(L, R, Key[4], Key[5]);
    GOSTEncryptRound(L, R, Key[6], Key[7]);
    GOSTEncryptRound(L, R, Key[7], Key[6]);
    GOSTEncryptRound(L, R, Key[5], Key[4]);
    GOSTEncryptRound(L, R, Key[3], Key[2]);
    GOSTEncryptRound(L, R, Key[1], Key[0]);
    s[i] := L;
    s[i + 1] := R;

    if i = 6 then Break;

    L := A xor C;
    R := B xor D;
    A := C;
    B := D;
    C := E;
    D := F;
    E := G;
    F := H;
    G := L;
    H := R;

    if i = 2 then
    begin
      A := A xor $FF00FF00;
      B := B xor $FF00FF00;
      C := C xor $00FF00FF;
      D := D xor $00FF00FF;
      E := E xor $00FFFF00;
      F := F xor $FF0000FF;
      G := G xor $000000FF;
      H := H xor $FF00FFFF;
    end;

    L := v[0];
    R := v[2];
    v[0] := v[4];
    v[2] := v[6];
    v[4] := L xor R;
    v[6] := v[0] xor R;
    L := v[1];
    R := v[3];
    v[1] := v[5];
    v[3] := v[7];
    v[5] := L xor R;
    v[7] := v[1] xor R;

    Inc(i, 2);
  end;

  {12 rounds of the LFSR (computed from a product matrix) and xor in M}

  A := PArray8Cardinal(Block)^[0] xor s[6];
  B := PArray8Cardinal(Block)^[1] xor s[7];
  C := PArray8Cardinal(Block)^[2] xor (s[0] shl 16) xor (s[0] shr 16) xor (s[0] and $ffff) xor (s[1] and $ffff) xor (s[1] shr 16) xor (s[2] shl 16) xor s[6] xor (s[6] shl 16) xor (s[7] and $ffff0000) xor (s[7] shr 16);
  D := PArray8Cardinal(Block)^[3] xor (s[0] and $ffff) xor (s[0] shl 16) xor (s[1] and $ffff) xor (s[1]                                                                      shl 16)
              xor (s[1] shr 16) xor (s[2] shl 16) xor (s[2] shr 16) xor (s[3] shl 16) xor s[6] xor (s[6] shl 16) xor (s[6] shr 16) xor (s[7] and $ffff) xor (s[7] shl 16) xor (s[7] shr 16);
  E := PArray8Cardinal(Block)^[4] xor (s[0] and $ffff0000) xor (s[0] shl 16) xor (s[0] shr 16) xor
    (s[1] and $ffff0000) xor (s[1] shr 16) xor (s[2] shl 16) xor (s[2] shr 16) xor (s[3] shl 16) xor (s[3] shr 16) xor (s[4] shl 16) xor (s[6] shl 16) xor (s[6] shr 16) xor (s[7] and $ffff) xor (s[7] shl 16) xor (s[7] shr 16);
  F := PArray8Cardinal(Block)^[5] xor (s[0] shl 16) xor (s[0] shr 16) xor (s[0] and $ffff0000) xor
    (s[1] and $ffff) xor s[2] xor (s[2] shr 16) xor (s[3] shl 16) xor (s[3] shr
                                                                    16) xor (s[4] shl 16) xor (s[4] shr 16) xor (s[5] shl 16) xor (s[6] shl 16) xor (s[6] shr 16) xor (s[7] and $ffff0000) xor (s[7] shl 16) xor (s[7] shr 16);
  G := PArray8Cardinal(Block)^[6] xor s[0] xor (s[1] shr 16) xor (s[2] shl 16) xor s[3] xor (s[3] shr 16)
              xor (s[4] shl 16) xor (s[4] shr 16) xor (s[5] shl 16) xor (s[5] shr 16) xor s[6] xor (s[6] shl 16) xor (s[6] shr 16) xor (s[7] shl 16);
  H := PArray8Cardinal(Block)^[7] xor (s[0] and $ffff0000) xor (s[0] shl 16) xor (s[1] and $ffff) xor
    (s[1] shl 16) xor (s[2] shr 16) xor (s[3] shl 16) xor s[4] xor (s[4] shr 16) xor (s[5] shl 16) xor (s[5] shr 16) xor (s[6] shr 16) xor (s[7] and $ffff) xor (s[7] shl 16) xor (s[7] shr 16);

  {16 * 1 round of the LFSR and xor in H}

  v[0] := FState[0] xor (B shl 16) xor (A shr 16);
  v[1] := FState[1] xor (C shl 16) xor (B shr 16);
  v[2] := FState[2] xor (D shl 16) xor (C shr 16);
  v[3] := FState[3] xor (E shl 16) xor (D shr 16);
  v[4] := FState[4] xor (F shl 16) xor (E shr 16);
  v[5] := FState[5] xor (G shl 16) xor (F shr 16);
  v[6] := FState[6] xor (H shl 16) xor (G shr 16);
  v[7] := FState[7] xor (A and $FFFF0000) xor (A shl 16) xor (H shr 16) xor
    (B and $FFFF0000) xor (B shl 16) xor (G shl 16) xor (H and $FFFF0000);

  {61 rounds of LFSR, mixing up h (computed from a product matrix)}

  FState[0] := (v[0] and $ffff0000) xor (v[0] shl 16) xor (v[0] shr 16) xor (v[1] shr 16) xor
             (v[1] and $ffff0000) xor (v[2] shl 16) xor (v[3] shr 16) xor (v[4] shl 16) xor
             (v[5] shr 16) xor v[5] xor (v[6] shr 16) xor (v[7] shl 16) xor (v[7] shr 16) xor
             (v[7] and $ffff);
  FState[1] := (v[0] shl 16) xor (v[0] shr 16) xor (v[0] and $ffff0000) xor (v[1] and $ffff) xor
              v[2] xor (v[2] shr 16) xor (v[3] shl 16) xor (v[4] shr 16) xor (v[5] shl 16) xor
             (v[6] shl 16) xor v[6] xor (v[7] and $ffff0000) xor (v[7] shr 16);
  FState[2] := (v[0] and $ffff) xor (v[0] shl 16) xor (v[1] shl 16) xor (v[1] shr 16) xor
             (v[1] and $ffff0000) xor (v[2] shl 16) xor (v[3] shr 16) xor v[3] xor
             (v[4] shl 16) xor (v[5] shr 16) xor v[6] xor (v[6] shr 16) xor (v[7] and $ffff) xor
             (v[7] shl 16) xor (v[7] shr 16);
  FState[3] := (v[0] shl 16) xor (v[0] shr 16) xor (v[0] and $ffff0000) xor (v[1] and $ffff0000) xor
             (v[1] shr 16) xor (v[2] shl 16) xor (v[2] shr 16) xor v[2] xor (v[3] shl 16) xor
             (v[4] shr 16) xor v[4] xor (v[5] shl 16) xor (v[6] shl 16) xor (v[7] and $ffff) xor
             (v[7] shr 16);
  FState[4] := (v[0] shr 16) xor (v[1] shl 16) xor v[1] xor (v[2] shr 16) xor v[2] xor
             (v[3] shl 16) xor (v[3] shr 16) xor v[3] xor (v[4] shl 16) xor (v[5] shr 16) xor
              v[5] xor (v[6] shl 16) xor (v[6] shr 16) xor (v[7] shl 16);
  FState[5] := (v[0] shl 16) xor (v[0] and $ffff0000) xor (v[1] shl 16) xor (v[1] shr 16) xor
             (v[1] and $ffff0000) xor (v[2] shl 16) xor v[2] xor (v[3] shr 16) xor v[3] xor
             (v[4] shl 16) xor (v[4] shr 16) xor v[4] xor (v[5] shl 16) xor (v[6] shl 16) xor
             (v[6] shr 16) xor v[6] xor (v[7] shl 16) xor (v[7] shr 16) xor (v[7] and $ffff0000);
  FState[6] := v[0] xor v[2] xor (v[2] shr 16) xor v[3] xor (v[3] shl 16) xor v[4] xor
            (v[4] shr 16) xor (v[5] shl 16) xor (v[5] shr 16) xor v[5] xor (v[6] shl 16) xor
            (v[6] shr 16) xor v[6] xor (v[7] shl 16) xor v[7];
  FState[7] := v[0] xor (v[0] shr 16) xor (v[1] shl 16) xor (v[1] shr 16) xor (v[2] shl 16) xor
            (v[3] shr 16) xor v[3] xor (v[4] shl 16) xor v[4] xor (v[5] shr 16) xor v[5] xor
            (v[6] shl 16) xor (v[6] shr 16) xor (v[7] shl 16) xor v[7];
end;

procedure THashGOST.UpdateBlock(const Block: Pointer);
var
  i: Integer;
  c: Boolean;
begin
  Inc(FLength, 32);

  c := False;
  for i := 0 to 7 do
  begin
    Inc(FSum[i], PArray8Cardinal(Block)^[i]);
    if c then
    begin
      Inc(FSum[i], 1);
      c := (FSum[i] <= PArray8Cardinal(Block)^[i]);
    end
    else
      c := (FSum[i] < PArray8Cardinal(Block)^[i]);
  end;
  
  Compress(Block);
end;

function THashGOST.GetPadBuffer: TBytes;
var
  PadLen, i: Word;
begin
  if FUsedBuffer > 0 then
  begin
    PadLen := 32 - FUsedBuffer;
    SetLength(Result, PadLen);
    for i := 0 to PadLen-1 do
      Result[i] := 0;
    //FillChar(Result[0], PadLen, 0);
  end
  else
    Result := nil;
end;

procedure THashGOST.Finalize;
var
  SaveLength: UInt64;
  LengthInBits: TArray8Cardinal;
begin
  Inc(FLength, FUsedBuffer);
  SaveLength := FLength shl 3;
  inherited; // pad buffer + update
  LengthInBits[0] := SaveLength and $FFFFFFFF; //Lo;
  LengthInBits[1] := (SaveLength shr 32) and $FFFFFFFF;//Hi;
  LengthInBits[2] := 0;
  LengthInBits[3] := 0;
  LengthInBits[4] := 0;
  LengthInBits[5] := 0;
  LengthInBits[6] := 0;
  LengthInBits[7] := 0;
  Compress(@LengthInBits);
  Compress(@FSum);

  SetValueFromBuffer(@FState[0], 32)
end;

end.
