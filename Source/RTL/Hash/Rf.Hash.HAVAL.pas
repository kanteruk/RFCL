{ *********************************************************************** }
{ Copyright (c) 2010-2017 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.Hash.HAVAL;

interface

uses Rf.Types, Rf.SysUtils, Rf.Hash;

type
  THashHAVALSize = (hhs128bit, hhs160bit, hhs192bit, hhs224bit, hhs256bit);
  THashHAVALPassCount = 3..5;

  /// <summary>
  /// HAVAL (HAVAL) 
  /// </summary>
  THashHAVAL = class(TBlockHash)
  private const
    HAVAL_VERSION = 1;
    HashSizeBytes: array[THashHAVALSize] of Byte = (16, 20, 24, 28, 32);
  private
    FState: array[0..7] of Cardinal;
    FHashSize: THashHAVALSize;
    FPassCount: THashHAVALPassCount;
    FLength: UInt64;
    procedure Tailor;
  protected
    procedure Initialize; override;
    procedure UpdateBlock(const BlockBuf: Pointer); override;
    function GetPadBuffer: TBytes; override;
    procedure Finalize; override;
  public
    constructor Create(const AHashSize: THashHAVALSize; const APassCount: THashHAVALPassCount = 5); virtual;

    class function HashType: THashType; override;
    function HashSize: Cardinal; override;

    property PassCount: THashHAVALPassCount read FPassCount;

    function BlockSize: Cardinal; override;
  end;

implementation

{ THashHAVAL }

class function THashHAVAL.HashType: THashType;
begin
  Result := THashType.Cryptographic;
end;

constructor THashHAVAL.Create(const AHashSize: THashHAVALSize; const APassCount: THashHAVALPassCount);
begin
  inherited Create;
  FHashSize := AHashSize;
  FPassCount := APassCount;
end;

function THashHAVAL.HashSize: Cardinal;
begin
  Result := HashSizeBytes[FHashSize];
end;

function THashHAVAL.BlockSize: Cardinal;
begin
  Result := 128;
end;

procedure THashHAVAL.Initialize;
begin
  inherited;
  FState[0] := $243F6A88;
  FState[1] := $85A308D3;
  FState[2] := $13198A2E;
  FState[3] := $03707344;
  FState[4] := $A4093822;
  FState[5] := $299F31D0;
  FState[6] := $082EFA98;
  FState[7] := $EC4E6C89;
  FLength := 0;
end;

procedure THashHAVAL.Tailor;
var
  T: Cardinal;
begin
  case FHashSize of
    hhs128bit:
    begin
      T := (FState[7] and $000000FF) or
           (FState[6] and $FF000000) or
           (FState[5] and $00FF0000) or
           (FState[4] and $0000FF00);
      Inc(FState[0], RotateRight(T,  8));

      T := (FState[7] and $0000FF00) or
           (FState[6] and $000000FF) or
           (FState[5] and $FF000000) or
           (FState[4] and $00FF0000);
      Inc(FState[1], RotateRight(T, 16));

      T := (FState[7] and $00FF0000) or
           (FState[6] and $0000FF00) or
           (FState[5] and $000000FF) or
           (FState[4] and $FF000000);
      Inc(FState[2], RotateRight(T, 24));

      T := (FState[7] and $FF000000) or
           (FState[6] and $00FF0000) or
           (FState[5] and $0000FF00) or
           (FState[4] and $000000FF);
      Inc(FState[3], T);
    end;
    hhs160bit:
    begin
      T := (FState[7] and  $3F) or
           (FState[6] and ($7F shl 25)) or
           (FState[5] and ($3F shl 19));
      Inc(FState[0], RotateRight(T, 19));
      T := (FState[7] and ($3F shl  6)) or
           (FState[6] and  $3F) or
           (FState[5] and ($7F shl 25));
      Inc(FState[1], RotateRight(T, 25));
      T := (FState[7] and ($7F shl 12)) or
           (FState[6] and ($3F shl  6)) or
           (FState[5] and  $3F);
      Inc(FState[2], T);
      T := (FState[7] and ($3F shl 19)) or
           (FState[6] and ($7F shl 12)) or
           (FState[5] and ($3F shl  6));
      Inc(FState[3], (T shr 6));
      T := (FState[7] and ($7F shl 25)) or
           (FState[6] and ($3F shl 19)) or
           (FState[5] and ($7F shl 12));
      Inc(FState[4], (T shr 12));
    end;
    hhs192bit:
    begin
      T := (FState[7] and  $1F) or
           (FState[6] and ($3F shl 26));
      Inc(FState[0], RotateRight(T, 26));
      T := (FState[7] and ($1F shl  5)) or
           (FState[6] and  $1F);
      Inc(FState[1], T);
      T := (FState[7] and ($3F shl 10)) or
           (FState[6] and ($1F shl  5));
      Inc(FState[2], (T shr 5));
      T := (FState[7] and ($1F shl 16)) or
           (FState[6] and ($3F shl 10));
      Inc(FState[3], (T shr 10));
      T := (FState[7] and ($1F shl 21)) or
           (FState[6] and ($1F shl 16));
      Inc(FState[4], (T shr 16));
      T := (FState[7] and ($3F shl 26)) or
           (FState[6] and ($1F shl 21));
      Inc(FState[5], (T shr 21));
    end;
    hhs224bit:
    begin
      Inc(FState[0], (FState[7] shr 27) and $1F);
      Inc(FState[1], (FState[7] shr 22) and $1F);
      Inc(FState[2], (FState[7] shr 18) and $0F);
      Inc(FState[3], (FState[7] shr 13) and $1F);
      Inc(FState[4], (FState[7] shr  9) and $0F);
      Inc(FState[5], (FState[7] shr  4) and $1F);
      Inc(FState[6], FState[7] and $0F);
    end;
    hhs256bit:;
  end;
end;

procedure THashHAVAL.UpdateBlock(const BlockBuf: Pointer);

  function F_1(const X6, X5, X4, X3, X2, X1, X0: Cardinal): Cardinal; inline;
  begin
    Result := (X1 and (X0 xor X4)) xor (X2 and X5) xor (X3 and X6) xor X0;
  end;

  function F_2(const X6, X5, X4, X3, X2, X1, X0: Cardinal): Cardinal; inline;
  begin
    Result := (X2 and (X1 and (not X3) xor X4 and X5 xor X6 xor X0) xor
      X4 and (X1 xor X5) xor X3 and X5 xor X0);
  end;

  function F_3(const X6, X5, X4, X3, X2, X1, X0: Cardinal): Cardinal; inline;
  begin
    Result := (X3 and (X1 and X2 xor X6 xor X0) xor X1 and X4 xor X2 and X5 xor X0);
  end;

  function F_4(const X6, X5, X4, X3, X2, X1, X0: Cardinal): Cardinal; inline;
  begin
    Result := (X4 and (X5 and (not X2) xor X3 and (not X6) xor X1 xor X6 xor X0) xor
      X3 and (X1 and X2 xor X5 xor X6) xor X2 and X6 xor X0);
  end;

  function F_5(const X6, X5, X4, X3, X2, X1, X0: Cardinal): Cardinal; inline;
  begin
    Result := (X0 and (X1 and X2 and X3 xor (not X5)) xor X1 and X4 xor X2 and X5 xor X3 and X6);
  end;


  procedure FF_1(var X7: Cardinal; const X6, X5, X4, X3, X2, X1, X0, w, PASS: Cardinal); inline;
  var
    t: Cardinal;
  begin
    if PASS = 3 then
      t := F_1(X1, X0, X3, X5, X6, X2, X4)
    else if PASS = 4 then
      t := F_1(X2, X6, X1, X4, X5, X3, X0)
    else
      t := F_1(X3, X4, X1, X0, X5, X2, X6);
    X7 := RotateRight(t, 7) + RotateRight(X7, 11) + w;
  end;

  procedure FF_2(var X7: Cardinal; const X6, X5, X4, X3, X2, X1, X0, w, c, PASS: Cardinal); inline;
  var
    t: Cardinal;
  begin
    if PASS = 3 then
      t := F_2(X4, X2, X1, X0, X5, X3, X6)
    else if PASS = 4 then
      t := F_2(X3, X5, X2, X0, X1, X6, X4)
    else
      t := F_2(X6, X2, X1, X0, X3, X4, X5);
    X7 := RotateRight(t, 7) + RotateRight(X7, 11) + w + c;
  end;

  procedure FF_3(var X7: Cardinal; const X6, X5, X4, X3, X2, X1, X0, w, c, PASS: Cardinal); inline;
  var
    t: Cardinal;
  begin
    if PASS = 3 then
      t := F_3(X6, X1, X2, X3, X4, X5, X0)
    else if PASS = 4 then
      t := F_3(X1, X4, X3, X6, X0, X2, X5)
    else
      t := F_3(X2, X6, X0, X4, X3, X1, X5);
    X7 := RotateRight(t, 7) + RotateRight(X7, 11) + w + c;
  end;

  procedure FF_4(var X7: Cardinal; const X6, X5, X4, X3, X2, X1, X0, w, c, PASS: Cardinal); inline;
  var
    t: Cardinal;
  begin
    if PASS = 4 then
      t := F_4(X6, X4, X0, X5, X2, X1, X3)
    else
      t := f_4(X1, X5, X3, X2, X0, X4, X6);
    X7 := RotateRight(t, 7) + RotateRight(X7, 11) + w + c;
  end;

  procedure FF_5(var X7: Cardinal; X6, X5, X4, X3, X2, X1, X0, w, c: Cardinal); inline;
  var
    t: Cardinal;
  begin
    t := F_5(X2, X5, X0, X6, X4, X3, X1);
    X7 := RotateRight(t, 7) + RotateRight(X7, 11) + w + c;
  end;

type
  TArray32Cardinal = array[0..31] of Cardinal;
  PArray32Cardinal = ^TArray32Cardinal;
var
  B: PArray32Cardinal absolute BlockBuf;
  T0, T1, T2, T3, T4, T5, T6, T7: Cardinal;
  PC: THashHAVALPassCount;
begin
  Inc(FLength, 128);

  PC := FPassCount;
  T0 := FState[0];
  T1 := FState[1];
  T2 := FState[2];
  T3 := FState[3];
  T4 := FState[4];
  T5 := FState[5];
  T6 := FState[6];
  T7 := FState[7];

  // Pass 1
  FF_1(T7, T6, T5, T4, T3, T2, T1, T0, B[00], PC);
  FF_1(T6, T5, T4, T3, T2, T1, T0, T7, B[01], PC);
  FF_1(T5, T4, T3, T2, T1, T0, T7, T6, B[02], PC);
  FF_1(T4, T3, T2, T1, T0, T7, T6, T5, B[03], PC);
  FF_1(T3, T2, T1, T0, T7, T6, T5, T4, B[04], PC);
  FF_1(T2, T1, T0, T7, T6, T5, T4, T3, B[05], PC);
  FF_1(T1, T0, T7, T6, T5, T4, T3, T2, B[06], PC);
  FF_1(T0, T7, T6, T5, T4, T3, T2, T1, B[07], PC);

  FF_1(T7, T6, T5, T4, T3, T2, T1, T0, B[08], PC);
  FF_1(T6, T5, T4, T3, T2, T1, T0, T7, B[09], PC);
  FF_1(T5, T4, T3, T2, T1, T0, T7, T6, B[10], PC);
  FF_1(T4, T3, T2, T1, T0, T7, T6, T5, B[11], PC);
  FF_1(T3, T2, T1, T0, T7, T6, T5, T4, B[12], PC);
  FF_1(T2, T1, T0, T7, T6, T5, T4, T3, B[13], PC);
  FF_1(T1, T0, T7, T6, T5, T4, T3, T2, B[14], PC);
  FF_1(T0, T7, T6, T5, T4, T3, T2, T1, B[15], PC);

  FF_1(T7, T6, T5, T4, T3, T2, T1, T0, B[16], PC);
  FF_1(T6, T5, T4, T3, T2, T1, T0, T7, B[17], PC);
  FF_1(T5, T4, T3, T2, T1, T0, T7, T6, B[18], PC);
  FF_1(T4, T3, T2, T1, T0, T7, T6, T5, B[19], PC);
  FF_1(T3, T2, T1, T0, T7, T6, T5, T4, B[20], PC);
  FF_1(T2, T1, T0, T7, T6, T5, T4, T3, B[21], PC);
  FF_1(T1, T0, T7, T6, T5, T4, T3, T2, B[22], PC);
  FF_1(T0, T7, T6, T5, T4, T3, T2, T1, B[23], PC);

  FF_1(T7, T6, T5, T4, T3, T2, T1, T0, B[24], PC);
  FF_1(T6, T5, T4, T3, T2, T1, T0, T7, B[25], PC);
  FF_1(T5, T4, T3, T2, T1, T0, T7, T6, B[26], PC);
  FF_1(T4, T3, T2, T1, T0, T7, T6, T5, B[27], PC);
  FF_1(T3, T2, T1, T0, T7, T6, T5, T4, B[28], PC);
  FF_1(T2, T1, T0, T7, T6, T5, T4, T3, B[29], PC);
  FF_1(T1, T0, T7, T6, T5, T4, T3, T2, B[30], PC);
  FF_1(T0, T7, T6, T5, T4, T3, T2, T1, B[31], PC);
                                              // PassCount 2
  FF_2(T7, T6, T5, T4, T3, T2, T1, T0, B[05], $452821E6, PC);
  FF_2(T6, T5, T4, T3, T2, T1, T0, T7, B[14], $38D01377, PC);
  FF_2(T5, T4, T3, T2, T1, T0, T7, T6, B[26], $BE5466CF, PC);
  FF_2(T4, T3, T2, T1, T0, T7, T6, T5, B[18], $34E90C6C, PC);
  FF_2(T3, T2, T1, T0, T7, T6, T5, T4, B[11], $C0AC29B7, PC);
  FF_2(T2, T1, T0, T7, T6, T5, T4, T3, B[28], $C97C50DD, PC);
  FF_2(T1, T0, T7, T6, T5, T4, T3, T2, B[07], $3F84D5B5, PC);
  FF_2(T0, T7, T6, T5, T4, T3, T2, T1, B[16], $B5470917, PC);

  FF_2(T7, T6, T5, T4, T3, T2, T1, T0, B[00], $9216D5D9, PC);
  FF_2(T6, T5, T4, T3, T2, T1, T0, T7, B[23], $8979FB1B, PC);
  FF_2(T5, T4, T3, T2, T1, T0, T7, T6, B[20], $D1310BA6, PC);
  FF_2(T4, T3, T2, T1, T0, T7, T6, T5, B[22], $98DFB5AC, PC);
  FF_2(T3, T2, T1, T0, T7, T6, T5, T4, B[01], $2FFD72DB, PC);
  FF_2(T2, T1, T0, T7, T6, T5, T4, T3, B[10], $D01ADFB7, PC);
  FF_2(T1, T0, T7, T6, T5, T4, T3, T2, B[04], $B8E1AFED, PC);
  FF_2(T0, T7, T6, T5, T4, T3, T2, T1, B[08], $6A267E96, PC);

  FF_2(T7, T6, T5, T4, T3, T2, T1, T0, B[30], $BA7C9045, PC);
  FF_2(T6, T5, T4, T3, T2, T1, T0, T7, B[03], $F12C7F99, PC);
  FF_2(T5, T4, T3, T2, T1, T0, T7, T6, B[21], $24A19947, PC);
  FF_2(T4, T3, T2, T1, T0, T7, T6, T5, B[09], $B3916CF7, PC);
  FF_2(T3, T2, T1, T0, T7, T6, T5, T4, B[17], $0801F2E2, PC);
  FF_2(T2, T1, T0, T7, T6, T5, T4, T3, B[24], $858EFC16, PC);
  FF_2(T1, T0, T7, T6, T5, T4, T3, T2, B[29], $636920D8, PC);
  FF_2(T0, T7, T6, T5, T4, T3, T2, T1, B[06], $71574E69, PC);

  FF_2(T7, T6, T5, T4, T3, T2, T1, T0, B[19], $A458FEA3, PC);
  FF_2(T6, T5, T4, T3, T2, T1, T0, T7, B[12], $F4933D7E, PC);
  FF_2(T5, T4, T3, T2, T1, T0, T7, T6, B[15], $0D95748F, PC);
  FF_2(T4, T3, T2, T1, T0, T7, T6, T5, B[13], $728EB658, PC);
  FF_2(T3, T2, T1, T0, T7, T6, T5, T4, B[02], $718BCD58, PC);
  FF_2(T2, T1, T0, T7, T6, T5, T4, T3, B[25], $82154AEE, PC);
  FF_2(T1, T0, T7, T6, T5, T4, T3, T2, B[31], $7B54A41D, PC);
  FF_2(T0, T7, T6, T5, T4, T3, T2, T1, B[27], $C25A59B5, PC);

  // PassCount 3
  FF_3(T7, T6, T5, T4, T3, T2, T1, T0, B[19], $9C30D539, PC);
  FF_3(T6, T5, T4, T3, T2, T1, T0, T7, B[09], $2AF26013, PC);
  FF_3(T5, T4, T3, T2, T1, T0, T7, T6, B[04], $C5D1B023, PC);
  FF_3(T4, T3, T2, T1, T0, T7, T6, T5, B[20], $286085F0, PC);
  FF_3(T3, T2, T1, T0, T7, T6, T5, T4, B[28], $CA417918, PC);
  FF_3(T2, T1, T0, T7, T6, T5, T4, T3, B[17], $B8DB38EF, PC);
  FF_3(T1, T0, T7, T6, T5, T4, T3, T2, B[08], $8E79DCB0, PC);
  FF_3(T0, T7, T6, T5, T4, T3, T2, T1, B[22], $603A180E, PC);

  FF_3(T7, T6, T5, T4, T3, T2, T1, T0, B[29], $6C9E0E8B, PC);
  FF_3(T6, T5, T4, T3, T2, T1, T0, T7, B[14], $B01E8A3E, PC);
  FF_3(T5, T4, T3, T2, T1, T0, T7, T6, B[25], $D71577C1, PC);
  FF_3(T4, T3, T2, T1, T0, T7, T6, T5, B[12], $BD314B27, PC);
  FF_3(T3, T2, T1, T0, T7, T6, T5, T4, B[24], $78AF2FDA, PC);
  FF_3(T2, T1, T0, T7, T6, T5, T4, T3, B[30], $55605C60, PC);
  FF_3(T1, T0, T7, T6, T5, T4, T3, T2, B[16], $E65525F3, PC);
  FF_3(T0, T7, T6, T5, T4, T3, T2, T1, B[26], $AA55AB94, PC);

  FF_3(T7, T6, T5, T4, T3, T2, T1, T0, B[31], $57489862, PC);
  FF_3(T6, T5, T4, T3, T2, T1, T0, T7, B[15], $63E81440, PC);
  FF_3(T5, T4, T3, T2, T1, T0, T7, T6, B[07], $55CA396A, PC);
  FF_3(T4, T3, T2, T1, T0, T7, T6, T5, B[03], $2AAB10B6, PC);
  FF_3(T3, T2, T1, T0, T7, T6, T5, T4, B[01], $B4CC5C34, PC);
  FF_3(T2, T1, T0, T7, T6, T5, T4, T3, B[00], $1141E8CE, PC);
  FF_3(T1, T0, T7, T6, T5, T4, T3, T2, B[18], $A15486AF, PC);
  FF_3(T0, T7, T6, T5, T4, T3, T2, T1, B[27], $7C72E993, PC);

  FF_3(T7, T6, T5, T4, T3, T2, T1, T0, B[13], $B3EE1411, PC);
  FF_3(T6, T5, T4, T3, T2, T1, T0, T7, B[06], $636FBC2A, PC);
  FF_3(T5, T4, T3, T2, T1, T0, T7, T6, B[21], $2BA9C55D, PC);
  FF_3(T4, T3, T2, T1, T0, T7, T6, T5, B[10], $741831F6, PC);
  FF_3(T3, T2, T1, T0, T7, T6, T5, T4, B[23], $CE5C3E16, PC);
  FF_3(T2, T1, T0, T7, T6, T5, T4, T3, B[11], $9B87931E, PC);
  FF_3(T1, T0, T7, T6, T5, T4, T3, T2, B[05], $AFD6BA33, PC);
  FF_3(T0, T7, T6, T5, T4, T3, T2, T1, B[02], $6C24CF5C, PC);

  // PassCount 4. executed only when PassCount = 4 or 5
  if PC >= 4 then
  begin
    FF_4(T7, T6, T5, T4, T3, T2, T1, T0, B[24], $7A325381, PC);
    FF_4(T6, T5, T4, T3, T2, T1, T0, T7, B[04], $28958677, PC);
    FF_4(T5, T4, T3, T2, T1, T0, T7, T6, B[00], $3B8F4898, PC);
    FF_4(T4, T3, T2, T1, T0, T7, T6, T5, B[14], $6B4BB9AF, PC);
    FF_4(T3, T2, T1, T0, T7, T6, T5, T4, B[02], $C4BFE81B, PC);
    FF_4(T2, T1, T0, T7, T6, T5, T4, T3, B[07], $66282193, PC);
    FF_4(T1, T0, T7, T6, T5, T4, T3, T2, B[28], $61D809CC, PC);
    FF_4(T0, T7, T6, T5, T4, T3, T2, T1, B[23], $FB21A991, PC);

    FF_4(T7, T6, T5, T4, T3, T2, T1, T0, B[26], $487CAC60, PC);
    FF_4(T6, T5, T4, T3, T2, T1, T0, T7, B[06], $5DEC8032, PC);
    FF_4(T5, T4, T3, T2, T1, T0, T7, T6, B[30], $EF845D5D, PC);
    FF_4(T4, T3, T2, T1, T0, T7, T6, T5, B[20], $E98575B1, PC);
    FF_4(T3, T2, T1, T0, T7, T6, T5, T4, B[18], $DC262302, PC);
    FF_4(T2, T1, T0, T7, T6, T5, T4, T3, B[25], $EB651B88, PC);
    FF_4(T1, T0, T7, T6, T5, T4, T3, T2, B[19], $23893E81, PC);
    FF_4(T0, T7, T6, T5, T4, T3, T2, T1, B[03], $D396ACC5, PC);

    FF_4(T7, T6, T5, T4, T3, T2, T1, T0, B[22], $0F6D6FF3, PC);
    FF_4(T6, T5, T4, T3, T2, T1, T0, T7, B[11], $83F44239, PC);
    FF_4(T5, T4, T3, T2, T1, T0, T7, T6, B[31], $2E0B4482, PC);
    FF_4(T4, T3, T2, T1, T0, T7, T6, T5, B[21], $A4842004, PC);
    FF_4(T3, T2, T1, T0, T7, T6, T5, T4, B[08], $69C8F04A, PC);
    FF_4(T2, T1, T0, T7, T6, T5, T4, T3, B[27], $9E1F9B5E, PC);
    FF_4(T1, T0, T7, T6, T5, T4, T3, T2, B[12], $21C66842, PC);
    FF_4(T0, T7, T6, T5, T4, T3, T2, T1, B[09], $F6E96C9A, PC);

    FF_4(T7, T6, T5, T4, T3, T2, T1, T0, B[01], $670C9C61, PC);
    FF_4(T6, T5, T4, T3, T2, T1, T0, T7, B[29], $ABD388F0, PC);
    FF_4(T5, T4, T3, T2, T1, T0, T7, T6, B[05], $6A51A0D2, PC);
    FF_4(T4, T3, T2, T1, T0, T7, T6, T5, B[15], $D8542F68, PC);
    FF_4(T3, T2, T1, T0, T7, T6, T5, T4, B[17], $960FA728, PC);
    FF_4(T2, T1, T0, T7, T6, T5, T4, T3, B[10], $AB5133A3, PC);
    FF_4(T1, T0, T7, T6, T5, T4, T3, T2, B[16], $6EEF0B6C, PC);
    FF_4(T0, T7, T6, T5, T4, T3, T2, T1, B[13], $137A3BE4, PC);
  end;

  // PassCount 5. executed only when PassCount = 5
  if PC = 5 then
  begin
    FF_5(T7, T6, T5, T4, T3, T2, T1, T0, B[27], $BA3BF050);
    FF_5(T6, T5, T4, T3, T2, T1, T0, T7, B[03], $7EFB2A98);
    FF_5(T5, T4, T3, T2, T1, T0, T7, T6, B[21], $A1F1651D);
    FF_5(T4, T3, T2, T1, T0, T7, T6, T5, B[26], $39AF0176);
    FF_5(T3, T2, T1, T0, T7, T6, T5, T4, B[17], $66CA593E);
    FF_5(T2, T1, T0, T7, T6, T5, T4, T3, B[11], $82430E88);
    FF_5(T1, T0, T7, T6, T5, T4, T3, T2, B[20], $8CEE8619);
    FF_5(T0, T7, T6, T5, T4, T3, T2, T1, B[29], $456F9FB4);

    FF_5(T7, T6, T5, T4, T3, T2, T1, T0, B[19], $7D84A5C3);
    FF_5(T6, T5, T4, T3, T2, T1, T0, T7, B[00], $3B8B5EBE);
    FF_5(T5, T4, T3, T2, T1, T0, T7, T6, B[12], $E06F75D8);
    FF_5(T4, T3, T2, T1, T0, T7, T6, T5, B[07], $85C12073);
    FF_5(T3, T2, T1, T0, T7, T6, T5, T4, B[13], $401A449F);
    FF_5(T2, T1, T0, T7, T6, T5, T4, T3, B[08], $56C16AA6);
    FF_5(T1, T0, T7, T6, T5, T4, T3, T2, B[31], $4ED3AA62);
    FF_5(T0, T7, T6, T5, T4, T3, T2, T1, B[10], $363F7706);

    FF_5(T7, T6, T5, T4, T3, T2, T1, T0, B[05], $1BFEDF72);
    FF_5(T6, T5, T4, T3, T2, T1, T0, T7, B[09], $429B023D);
    FF_5(T5, T4, T3, T2, T1, T0, T7, T6, B[14], $37D0D724);
    FF_5(T4, T3, T2, T1, T0, T7, T6, T5, B[30], $D00A1248);
    FF_5(T3, T2, T1, T0, T7, T6, T5, T4, B[18], $DB0FEAD3);
    FF_5(T2, T1, T0, T7, T6, T5, T4, T3, B[06], $49F1C09B);
    FF_5(T1, T0, T7, T6, T5, T4, T3, T2, B[28], $075372C9);
    FF_5(T0, T7, T6, T5, T4, T3, T2, T1, B[24], $80991B7B);

    FF_5(T7, T6, T5, T4, T3, T2, T1, T0, B[02], $25D479D8);
    FF_5(T6, T5, T4, T3, T2, T1, T0, T7, B[23], $F6E8DEF7);
    FF_5(T5, T4, T3, T2, T1, T0, T7, T6, B[16], $E3FE501A);
    FF_5(T4, T3, T2, T1, T0, T7, T6, T5, B[22], $B6794C3B);
    FF_5(T3, T2, T1, T0, T7, T6, T5, T4, B[04], $976CE0BD);
    FF_5(T2, T1, T0, T7, T6, T5, T4, T3, B[01], $04C006BA);
    FF_5(T1, T0, T7, T6, T5, T4, T3, T2, B[25], $C1A94FB6);
    FF_5(T0, T7, T6, T5, T4, T3, T2, T1, B[15], $409F60C4);
  end;

  Inc(FState[0], T0);
  Inc(FState[1], T1);
  Inc(FState[2], T2);
  Inc(FState[3], T3);
  Inc(FState[4], T4);
  Inc(FState[5], T5);
  Inc(FState[6], T6);
  Inc(FState[7], T7);
end;

function THashHAVAL.GetPadBuffer: TBytes;
var
  i, PadLen: Cardinal;
  HashSizeInBits: Word;
  LengthinBits: UInt64;
begin
  Inc(FLength, FUsedBuffer);
  HashSizeInBits := HashSizeBytes[FHashSize] shl 3;
  LengthinBits := FLength shl 3;
  // pad out to 118 mod 128
  if FUsedBuffer < 118 then
    PadLen := 118 - FUsedBuffer
  else
    PadLen := 246 - FUsedBuffer;
  SetLength(Result, PadLen + 10);
  Result[0] := $01;
  for i := 1 to PadLen - 1 do
    Result[i] := 0;

  Result[PadLen+0] := ((HashSizeInBits and $3) shl 6) or ((FPassCount and $7) shl 3) or (HAVAL_VERSION and $7);
  Result[PadLen+1] := (HashSizeInBits shr 2) and $FF;
  PUInt64(@Result[PadLen+2])^ := LengthInBits;
//  Move(LengthinBits, Result[PadLen+2], 8);
end;

procedure THashHAVAL.Finalize;
begin
  inherited;
  Tailor;
  SetValueFromBuffer(@FState[0], HashSizeBytes[FHashSize]);
end;

end.
