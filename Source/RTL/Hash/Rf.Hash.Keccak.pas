{ *********************************************************************** }
{ Copyright (c) 2010-2018 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.Hash.Keccak;

interface

uses Rf.Types, Rf.SysUtils, Rf.Hash;

type

  /// <summary>
  /// Keccak
  /// </summary>
  THashKeccak = class(TBlockHash)
  private
    FHashSize: Cardinal;
    FBlockSize: Integer;
    FState: array [0..24] of UInt64;
    FBlockSize64: Cardinal;
  protected
    procedure Initialize; override;
    procedure UpdateBlock(const Block: Pointer); override;
    function GetPadBuffer: TBytes; override;
    procedure Finalize; override;
  public
    class function HashType: THashType; override;
    function HashSize: Cardinal; override;
    function BlockSize: Cardinal; override;
    constructor Create(const AHashSize: Cardinal = 32); virtual;
    procedure AfterConstruction; override;
  end;

  THashKeccak_224 = class(THashKeccak)
  public
    constructor Create; reintroduce; virtual;
  end;

  THashKeccak_256 = class(THashKeccak)
  public
    constructor Create; reintroduce; virtual;
  end;

  THashKeccak_384 = class(THashKeccak)
  public
    constructor Create; reintroduce; virtual;
  end;

  THashKeccak_512 = class(THashKeccak)
  public
    constructor Create; reintroduce; virtual;
  end;

implementation

type
  TArray16UInt64 = array [0..24] of UInt64;

{ THashKeccak }

class function THashKeccak.HashType: THashType;
begin
  Result := THashType.Cryptographic;
end;

constructor THashKeccak.Create(const AHashSize: Cardinal);
begin
  inherited Create;
  FHashSize := AHashSize;
end;

procedure THashKeccak.AfterConstruction;
begin
  FBlockSize := (200 - 2 * FHashSize); // 28, 32, 48, 64, ...
  FBlockSize64 := FBlockSize div 8;
  inherited;
end;

function THashKeccak.HashSize: Cardinal;
begin
  Result := FHashSize;
end;

function THashKeccak.BlockSize: Cardinal;
begin
  Result := FBlockSize;
end;

procedure THashKeccak.Initialize;
begin
  inherited;
  FillChar(FState, SizeOf(FState), 0);
end;

{ procedure THashKeccak.UpdateBlock(const Block: Pointer);
  const
  Mod5: array[-1..20] of Integer = (4, 0,1,2,3,4, 0,1,2,3,4, 0,1,2,3,4, 0,1,2,3,4, 0); // analog = x mod 5, but fasters

  RoundConst: array [0..23] of UInt64 = (
  $0000000000000001, $0000000000008082, $800000000000808a,
  $8000000080008000, $000000000000808b, $0000000080000001,
  $8000000080008081, $8000000000008009, $000000000000008a,
  $0000000000000088, $0000000080008009, $000000008000000a,
  $000000008000808b, $800000000000008b, $8000000000008089,
  $8000000000008003, $8000000000008002, $8000000000000080,
  $000000000000800a, $800000008000000a, $8000000080008081,
  $8000000000008080, $0000000080000001, $8000000080008008
  );
  RotOffset: array[0..4,0..4] of Byte = (
  (0, 36, 3, 41, 18),
  (1, 44, 10, 45, 2),
  (62, 6, 43, 15, 61),
  (28, 55, 25, 21, 56),
  (27, 20, 39, 8, 14));

  type
  PArray16UInt64 = ^TArray16UInt64;
  TArray16UInt64 = array[0..24] of UInt64;

  TMatrixRec = record
  A: array[0..4,0..4] of UInt64;
  end;

  var
  i: Integer;
  iRound: Integer;
  B: array[0..4,0..4] of UInt64;
  C, D: array[0..4] of UInt64;
  x, y: Integer;
  begin
  for i := 0 to FBlockSize64 - 1 do
  FState[i] := FState[i] xor PArray16UInt64(Block)[i];

  with TMatrixRec(FState) do
  for iRound := 0 to 23 do
  begin
  for x := 0 to 4 do
  C[x] := A[0,x] xor A[1,x] xor A[2,x] xor A[3,x] xor A[4,x];

  for x := 0 to 4 do
  begin
  D[x] := C[Mod5[x-1]] xor RotateLeft(C[Mod5[x+1]], 1);
  for y := 0 to 4 do
  A[y,x] := A[y,x] xor D[x];
  end;

  for x := 0 to 4 do
  for y := 0 to 4 do
  B[y, Mod5[x*2 + 3*y]] := RotateLeft(A[y,x], RotOffset[x,y]);

  for x := 0 to 4 do
  for y := 0 to 4 do
  A[y,x] := B[x,y] xor (not B[Mod5[x+1], y] and B[Mod5[x+2], y]);

  FState[0] := FState[0] xor RoundConst[iRound];
  end;

  end; }

procedure xorIntoState(var state: TArray16UInt64; inp: Pointer; laneCount: Integer);
var
  pI, pS: PUInt64;
  i: Integer;
begin
  pI := PUInt64(inp);
  pS := PUInt64(@state[0]);
  for i := laneCount - 1 downto 0 do
  begin
    pS^ := pS^ xor pI^;
    inc(pI);
    inc(pS);
  end;
end;

procedure THashKeccak.UpdateBlock(const Block: Pointer);
const
  RoundConst: array [0..23] of UInt64 = ($0000000000000001, $0000000000008082,
    $800000000000808A, $8000000080008000, $000000000000808B, $0000000080000001,
    $8000000080008081, $8000000000008009, $000000000000008A, $0000000000000088,
    $0000000080008009, $000000008000000A, $000000008000808B, $800000000000008B,
    $8000000000008089, $8000000000008003, $8000000000008002, $8000000000000080,
    $000000000000800A, $800000008000000A, $8000000080008081, $8000000000008080,
    $0000000080000001, $8000000080008008);

var
  {i,} iRound: Integer;
  A, B: TArray16UInt64;
  C0, C1, C2, C3, C4, D0, D1, D2, D3, D4: UInt64;
begin
  A := TArray16UInt64(FState);
  xorIntoState(A, Block, FBlockSize64);

{  for i := FBlockSize64 - 1 downto 0 do
    A[i] := A[i] xor TArray16UInt64(Block^)[i];}

  for iRound := 0 to 23 do
  begin
    C0 := A[0] xor A[5] xor A[10] xor A[15] xor A[20];
    C1 := A[1] xor A[6] xor A[11] xor A[16] xor A[21];
    C2 := A[2] xor A[7] xor A[12] xor A[17] xor A[22];
    C3 := A[3] xor A[8] xor A[13] xor A[18] xor A[23];
    C4 := A[4] xor A[9] xor A[14] xor A[19] xor A[24];

    D0 := C4 xor RotateLeft(C1, 1);
    D1 := C0 xor RotateLeft(C2, 1);
    D2 := C1 xor RotateLeft(C3, 1);
    D3 := C2 xor RotateLeft(C4, 1);
    D4 := C3 xor RotateLeft(C0, 1);

    B[00] := A[00] xor D0;
    B[02] := RotateLeft(A[01] xor D1, 1);
    B[04] := RotateLeft(A[02] xor D2, 62);
    B[01] := RotateLeft(A[03] xor D3, 28);
    B[03] := RotateLeft(A[04] xor D4, 27);
    B[08] := RotateLeft(A[05] xor D0, 36);
    B[05] := RotateLeft(A[06] xor D1, 44);
    B[07] := RotateLeft(A[07] xor D2, 6);
    B[09] := RotateLeft(A[08] xor D3, 55);
    B[06] := RotateLeft(A[09] xor D4, 20);
    B[11] := RotateLeft(A[10] xor D0, 3);
    B[13] := RotateLeft(A[11] xor D1, 10);
    B[10] := RotateLeft(A[12] xor D2, 43);
    B[12] := RotateLeft(A[13] xor D3, 25);
    B[14] := RotateLeft(A[14] xor D4, 39);
    B[19] := RotateLeft(A[15] xor D0, 41);
    B[16] := RotateLeft(A[16] xor D1, 45);
    B[18] := RotateLeft(A[17] xor D2, 15);
    B[15] := RotateLeft(A[18] xor D3, 21);
    B[17] := RotateLeft(A[19] xor D4, 8);
    B[22] := RotateLeft(A[20] xor D0, 18);
    B[24] := RotateLeft(A[21] xor D1, 2);
    B[21] := RotateLeft(A[22] xor D2, 61);
    B[23] := RotateLeft(A[23] xor D3, 56);
    B[20] := RotateLeft(A[24] xor D4, 14);

    A[00] := B[00] xor (not B[05] and B[10]);
    A[01] := B[05] xor (not B[10] and B[15]);
    A[02] := B[10] xor (not B[15] and B[20]);
    A[03] := B[15] xor (not B[20] and B[00]);
    A[04] := B[20] xor (not B[00] and B[05]);
    A[05] := B[01] xor (not B[06] and B[11]);
    A[06] := B[06] xor (not B[11] and B[16]);
    A[07] := B[11] xor (not B[16] and B[21]);
    A[08] := B[16] xor (not B[21] and B[01]);
    A[09] := B[21] xor (not B[01] and B[06]);
    A[10] := B[02] xor (not B[07] and B[12]);
    A[11] := B[07] xor (not B[12] and B[17]);
    A[12] := B[12] xor (not B[17] and B[22]);
    A[13] := B[17] xor (not B[22] and B[02]);
    A[14] := B[22] xor (not B[02] and B[07]);
    A[15] := B[03] xor (not B[08] and B[13]);
    A[16] := B[08] xor (not B[13] and B[18]);
    A[17] := B[13] xor (not B[18] and B[23]);
    A[18] := B[18] xor (not B[23] and B[03]);
    A[19] := B[23] xor (not B[03] and B[08]);
    A[20] := B[04] xor (not B[09] and B[14]);
    A[21] := B[09] xor (not B[14] and B[19]);
    A[22] := B[14] xor (not B[19] and B[24]);
    A[23] := B[19] xor (not B[24] and B[04]);
    A[24] := B[24] xor (not B[04] and B[09]);

    A[0] := A[0] xor RoundConst[iRound];
  end;
  TArray16UInt64(FState) := A;
end;

function THashKeccak.GetPadBuffer: TBytes;
var
  i, PadLen: Integer;
begin
  PadLen := BlockSize - FUsedBuffer;
  SetLength(Result, PadLen);
  if PadLen = 1 then
    Result[0] := $81
  else if PadLen > 1 then
  begin
    Result[0] := $01;
    for i := 1 to High(Result) - 1 do
      Result[i] := 0;
    Result[High(Result)] := $80;
  end;
end;

procedure THashKeccak.Finalize;
begin
  inherited;
  SetValueFromBuffer(@FState, FHashSize);
end;

{ THashKeccak_224 }

constructor THashKeccak_224.Create;
begin
  inherited Create(28);
end;

{ THashKeccak_256 }

constructor THashKeccak_256.Create;
begin
  inherited Create(32);
end;

{ THashKeccak_384 }

constructor THashKeccak_384.Create;
begin
  inherited Create(48);
end;

{ THashKeccak_512 }

constructor THashKeccak_512.Create;
begin
  inherited Create(64);
end;

end.
