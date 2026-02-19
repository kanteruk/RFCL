{ *********************************************************************** }
{ Copyright (c) 2010-2011 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.Hash.Panama;

interface

uses Rf.Types, Rf.SysUtils, Rf.Hash;

type

  /// <summary>
  /// Panama Hash Algorithm 256 Bit (Panama256)
  /// </summary>
  THashPanama = class(TBlockHash)
  private
    FState: array[0..16] of Cardinal;
    FStages: array[0..31, 0..7] of Cardinal;
    FTap: Cardinal;
  protected
    procedure Initialize; override;
    procedure UpdateBlock(const Block: Pointer); override;
    function GetPadBuffer: TBytes; override;
    procedure Finalize; override;
    procedure GetValue(var Value: TBytes);
  public
    class function HashType: THashType; override;
    function HashSize: Cardinal; override;
    function BlockSize: Cardinal; override;
  end;

implementation

{ THashPanama }

class function THashPanama.HashType: THashType;
begin
  Result := THashType.Cryptographic;
end;

function THashPanama.HashSize: Cardinal;
begin
  Result := 32;
end;

function THashPanama.BlockSize: Cardinal;
begin
  Result := 32;
end;

procedure THashPanama.Initialize;
var
  i, j: Integer;
begin
  inherited;
  for i := 0 to 16 do
    FState[i] := 0;
  for i := 0 to 31 do
    for j := 0 to 7 do
      FStages[i, j] := 0;
  FTap := 0;
end;

procedure THashPanama.UpdateBlock(const Block: Pointer);
type
  PArray16UINT = ^TArray16UINT;
  TArray16UINT = array[0..15] of Cardinal;
const
  cMod32 = $1F;
var
  X0, X1, X2, X3, X4, X5, X6, X7: Cardinal;
  Gamma: array[0..16] of Cardinal;
  pi: array[0..16] of Cardinal;
  Theta: array[0..16] of Cardinal;
  S: array[0..16] of Cardinal;
  tap16, tap25: Cardinal;
  i: Integer;
begin
  X0 := PArray16UINT(Block)^[0];
  X1 := PArray16UINT(Block)^[1];
  X2 := PArray16UINT(Block)^[2];
  X3 := PArray16UINT(Block)^[3];
  X4 := PArray16UINT(Block)^[4];
  X5 := PArray16UINT(Block)^[5];
  X6 := PArray16UINT(Block)^[6];
  X7 := PArray16UINT(Block)^[7];

{  for i := 0 to 16 do
    S[i] := FState[i]; }
  Move(FState, S, SizeOf(FState));

  Gamma[00] := S[00] xor (S[01] or not S[02]);
  Gamma[01] := S[01] xor (S[02] or not S[03]);
  Gamma[02] := S[02] xor (S[03] or not S[04]);
  Gamma[03] := S[03] xor (S[04] or not S[05]);
  Gamma[04] := S[04] xor (S[05] or not S[06]);
  Gamma[05] := S[05] xor (S[06] or not S[07]);
  Gamma[06] := S[06] xor (S[07] or not S[08]);
  Gamma[07] := S[07] xor (S[08] or not S[09]);
  Gamma[08] := S[08] xor (S[09] or not S[10]);
  Gamma[09] := S[09] xor (S[10] or not S[11]);
  Gamma[10] := S[10] xor (S[11] or not S[12]);
  Gamma[11] := S[11] xor (S[12] or not S[13]);
  Gamma[12] := S[12] xor (S[13] or not S[14]);
  Gamma[13] := S[13] xor (S[14] or not S[15]);
  Gamma[14] := S[14] xor (S[15] or not S[16]);
  Gamma[15] := S[15] xor (S[16] or not S[00]);
  Gamma[16] := S[16] xor (S[00] or not S[01]);

  pi[00] := Gamma[0];
  pi[01] := (Gamma[07] shl 1 ) or RotateRight(Gamma[07], 31);
  pi[02] := (Gamma[14] shl 3 ) or RotateRight(Gamma[14], 29);
  pi[03] := (Gamma[04] shl 6 ) or RotateRight(Gamma[04], 26);
  pi[04] := (Gamma[11] shl 10) or RotateRight(Gamma[11], 22);
  pi[05] := (Gamma[01] shl 15) or RotateRight(Gamma[01], 17);
  pi[06] := (Gamma[08] shl 21) or RotateRight(Gamma[08], 11);
  pi[07] := (Gamma[15] shl 28) or RotateRight(Gamma[15], 4);
  pi[08] := (Gamma[05] shl 4 ) or RotateRight(Gamma[05], 28);
  pi[09] := (Gamma[12] shl 13) or RotateRight(Gamma[12], 19);
  pi[10] := (Gamma[02] shl 23) or RotateRight(Gamma[02], 9);
  pi[11] := (Gamma[09] shl 2 ) or RotateRight(Gamma[09], 30);
  pi[12] := (Gamma[16] shl 14) or RotateRight(Gamma[16], 18);
  pi[13] := (Gamma[06] shl 27) or RotateRight(Gamma[06], 5);
  pi[14] := (Gamma[13] shl 9 ) or RotateRight(Gamma[13], 23);
  pi[15] := (Gamma[03] shl 24) or RotateRight(Gamma[03], 8);
  pi[16] := (Gamma[10] shl 8 ) or RotateRight(Gamma[10], 24);

  Theta[00] := pi[00] xor pi[01] xor pi[04];
  Theta[01] := pi[01] xor pi[02] xor pi[05];
  Theta[02] := pi[02] xor pi[03] xor pi[06];
  Theta[03] := pi[03] xor pi[04] xor pi[07];
  Theta[04] := pi[04] xor pi[05] xor pi[08];
  Theta[05] := pi[05] xor pi[06] xor pi[09];
  Theta[06] := pi[06] xor pi[07] xor pi[10];
  Theta[07] := pi[07] xor pi[08] xor pi[11];
  Theta[08] := pi[08] xor pi[09] xor pi[12];
  Theta[09] := pi[09] xor pi[10] xor pi[13];
  Theta[10] := pi[10] xor pi[11] xor pi[14];
  Theta[11] := pi[11] xor pi[12] xor pi[15];
  Theta[12] := pi[12] xor pi[13] xor pi[16];
  Theta[13] := pi[13] xor pi[14] xor pi[00];
  Theta[14] := pi[14] xor pi[15] xor pi[01];
  Theta[15] := pi[15] xor pi[16] xor pi[02];
  Theta[16] := pi[16] xor pi[00] xor pi[03];

  tap16 := (FTap + 16) and cMod32;
  FTap  := (FTap - 1)  and cMod32;
  tap25 := (FTap + 25) and cMod32;

  FStages[tap25,0] := FStages[tap25,0] xor FStages[ftap,2];
  FStages[tap25,1] := FStages[tap25,1] xor FStages[ftap,3];
  FStages[tap25,2] := FStages[tap25,2] xor FStages[ftap,4];
  FStages[tap25,3] := FStages[tap25,3] xor FStages[ftap,5];
  FStages[tap25,4] := FStages[tap25,4] xor FStages[ftap,6];
  FStages[tap25,5] := FStages[tap25,5] xor FStages[ftap,7];
  FStages[tap25,6] := FStages[tap25,6] xor FStages[ftap,0];
  FStages[tap25,7] := FStages[tap25,7] xor FStages[ftap,1];
  FStages[ftap,0]  := FStages[ftap,0] xor X0;
  FStages[ftap,1]  := FStages[ftap,1] xor X1;
  FStages[ftap,2]  := FStages[ftap,2] xor X2;
  FStages[ftap,3]  := FStages[ftap,3] xor X3;
  FStages[ftap,4]  := FStages[ftap,4] xor X4;
  FStages[ftap,5]  := FStages[ftap,5] xor X5;
  FStages[ftap,6]  := FStages[ftap,6] xor X6;
  FStages[ftap,7]  := FStages[ftap,7] xor X7;

  S[00] := Theta[00] xor $01;
  S[01] := Theta[01] xor X0;
  S[02] := Theta[02] xor X1;
  S[03] := Theta[03] xor X2;
  S[04] := Theta[04] xor X3;
  S[05] := Theta[05] xor X4;
  S[06] := Theta[06] xor X5;
  S[07] := Theta[07] xor X6;
  S[08] := Theta[08] xor X7;
  S[09] := Theta[09] xor FStages[tap16,0];
  S[10] := Theta[10] xor FStages[tap16,1];
  S[11] := Theta[11] xor FStages[tap16,2];
  S[12] := Theta[12] xor FStages[tap16,3];
  S[13] := Theta[13] xor FStages[tap16,4];
  S[14] := Theta[14] xor FStages[tap16,5];
  S[15] := Theta[15] xor FStages[tap16,6];
  S[16] := Theta[16] xor FStages[tap16,7];

  for i := 0 to 16 do
    FState[i] := S[i];
end;

function THashPanama.GetPadBuffer: TBytes;
var
  i: Word;
  Len: Word;
begin
  if FUsedBuffer = 0 then
    Len := BlockSize
  else
    Len := BlockSize - FUsedBuffer;
  SetLength(Result, Len);
  Result[0] := 1;
  for i := 1 to Len-1 do
    Result[i] := 0;
end;

procedure THashPanama.GetValue(var Value: TBytes);
const
  cMod32 = $1F;
var
  Gamma: array[0..16] of Cardinal;
  pi: array[0..16] of Cardinal;
  Theta: array[0..16] of Cardinal;
  S: array[0..16] of Cardinal;
  hash: array[0..7] of Cardinal;
  tap4, tap16, tap25: Cardinal;
  i, j: Integer;
begin
  for i := 0 to 16 do
    S[i] := FState[i];
  for i := 0 to 32 do
  begin
    for j := 0 to 7 do
      hash[j] := S[9+j];

    Gamma[00] := S[00] xor (S[01] or not S[02]);
    Gamma[01] := S[01] xor (S[02] or not S[03]);
    Gamma[02] := S[02] xor (S[03] or not S[04]);
    Gamma[03] := S[03] xor (S[04] or not S[05]);
    Gamma[04] := S[04] xor (S[05] or not S[06]);
    Gamma[05] := S[05] xor (S[06] or not S[07]);
    Gamma[06] := S[06] xor (S[07] or not S[08]);
    Gamma[07] := S[07] xor (S[08] or not S[09]);
    Gamma[08] := S[08] xor (S[09] or not S[10]);
    Gamma[09] := S[09] xor (S[10] or not S[11]);
    Gamma[10] := S[10] xor (S[11] or not S[12]);
    Gamma[11] := S[11] xor (S[12] or not S[13]);
    Gamma[12] := S[12] xor (S[13] or not S[14]);
    Gamma[13] := S[13] xor (S[14] or not S[15]);
    Gamma[14] := S[14] xor (S[15] or not S[16]);
    Gamma[15] := S[15] xor (S[16] or not S[00]);
    Gamma[16] := S[16] xor (S[00] or not S[01]);

    pi[00] := Gamma[0];
    pi[01] := (Gamma[07] shl 1)  or RotateRight(Gamma[07], 31);
    pi[02] := (Gamma[14] shl 3)  or RotateRight(Gamma[14], 29);
    pi[03] := (Gamma[04] shl 6)  or RotateRight(Gamma[04], 26);
    pi[04] := (Gamma[11] shl 10) or RotateRight(Gamma[11], 22);
    pi[05] := (Gamma[01] shl 15) or RotateRight(Gamma[01], 17);
    pi[06] := (Gamma[08] shl 21) or RotateRight(Gamma[08], 11);
    pi[07] := (Gamma[15] shl 28) or RotateRight(Gamma[15], 4);
    pi[08] := (Gamma[05] shl 4)  or RotateRight(Gamma[05], 28);
    pi[09] := (Gamma[12] shl 13) or RotateRight(Gamma[12], 19);
    pi[10] := (Gamma[02] shl 23) or RotateRight(Gamma[02], 9);
    pi[11] := (Gamma[09] shl 2)  or RotateRight(Gamma[09], 30);
    pi[12] := (Gamma[16] shl 14) or RotateRight(Gamma[16], 18);
    pi[13] := (Gamma[06] shl 27) or RotateRight(Gamma[06], 5);
    pi[14] := (Gamma[13] shl 9)  or RotateRight(Gamma[13], 23);
    pi[15] := (Gamma[03] shl 24) or RotateRight(Gamma[03], 8);
    pi[16] := (Gamma[10] shl 8)  or RotateRight(Gamma[10], 24);

    Theta[00] := pi[00] xor pi[01] xor pi[04];
    Theta[01] := pi[01] xor pi[02] xor pi[05];
    Theta[02] := pi[02] xor pi[03] xor pi[06];
    Theta[03] := pi[03] xor pi[04] xor pi[07];
    Theta[04] := pi[04] xor pi[05] xor pi[08];
    Theta[05] := pi[05] xor pi[06] xor pi[09];
    Theta[06] := pi[06] xor pi[07] xor pi[10];
    Theta[07] := pi[07] xor pi[08] xor pi[11];
    Theta[08] := pi[08] xor pi[09] xor pi[12];
    Theta[09] := pi[09] xor pi[10] xor pi[13];
    Theta[10] := pi[10] xor pi[11] xor pi[14];
    Theta[11] := pi[11] xor pi[12] xor pi[15];
    Theta[12] := pi[12] xor pi[13] xor pi[16];
    Theta[13] := pi[13] xor pi[14] xor pi[00];
    Theta[14] := pi[14] xor pi[15] xor pi[01];
    Theta[15] := pi[15] xor pi[16] xor pi[02];
    Theta[16] := pi[16] xor pi[00] xor pi[03];

    tap4  := (Ftap + 4)  and cMod32;
    tap16 := (Ftap + 16) and cMod32;
    ftap  := (Ftap - 1)  and cMod32;
    tap25 := (Ftap + 25) and cMod32;

    FStages[tap25,0] := FStages[tap25,0] xor FStages[ftap,2];
    FStages[tap25,1] := FStages[tap25,1] xor FStages[ftap,3];
    FStages[tap25,2] := FStages[tap25,2] xor FStages[ftap,4];
    FStages[tap25,3] := FStages[tap25,3] xor FStages[ftap,5];
    FStages[tap25,4] := FStages[tap25,4] xor FStages[ftap,6];
    FStages[tap25,5] := FStages[tap25,5] xor FStages[ftap,7];
    FStages[tap25,6] := FStages[tap25,6] xor FStages[ftap,0];
    FStages[tap25,7] := FStages[tap25,7] xor FStages[ftap,1];
    FStages[ftap,0]  := FStages[ftap,0] xor S[1];
    FStages[ftap,1]  := FStages[ftap,1] xor S[2];
    FStages[ftap,2]  := FStages[ftap,2] xor S[3];
    FStages[ftap,3]  := FStages[ftap,3] xor S[4];
    FStages[ftap,4]  := FStages[ftap,4] xor S[5];
    FStages[ftap,5]  := FStages[ftap,5] xor S[6];
    FStages[ftap,6]  := FStages[ftap,6] xor S[7];
    FStages[ftap,7]  := FStages[ftap,7] xor S[8];

    S[00] := Theta[00] xor $01;
    S[01] := Theta[01] xor FStages[tap4,0];
    S[02] := Theta[02] xor FStages[tap4,1];
    S[03] := Theta[03] xor FStages[tap4,2];
    S[04] := Theta[04] xor FStages[tap4,3];
    S[05] := Theta[05] xor FStages[tap4,4];
    S[06] := Theta[06] xor FStages[tap4,5];
    S[07] := Theta[07] xor FStages[tap4,6];
    S[08] := Theta[08] xor FStages[tap4,7];
    S[09] := Theta[09] xor FStages[tap16,0];
    S[10] := Theta[10] xor FStages[tap16,1];
    S[11] := Theta[11] xor FStages[tap16,2];
    S[12] := Theta[12] xor FStages[tap16,3];
    S[13] := Theta[13] xor FStages[tap16,4];
    S[14] := Theta[14] xor FStages[tap16,5];
    S[15] := Theta[15] xor FStages[tap16,6];
    S[16] := Theta[16] xor FStages[tap16,7];
  end;

  for i := 0 to 16 do
    FState[i] := S[i];

  Move(hash[0], Value[0], SizeOf(hash));
end;

procedure THashPanama.Finalize;
begin
  inherited;
  //SetValueFromBuffer();
  GetValue(FValue);
end;

end.
