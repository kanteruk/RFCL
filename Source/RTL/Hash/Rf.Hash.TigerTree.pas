{ *********************************************************************** }
{ Copyright (c) 2010-2011 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.Hash.TigerTree;

interface

uses System.SysUtils, Rf.Types, Rf.Hash, Rf.Hash.Tiger;

type

  /// <summary>
  /// Tiger Tree Hash Algorithm 192 Bit (TTH)
  /// </summary>
  THashTigerTree = class(TBlockHash)
  private
    FPassCount: Word;
    Nodes: array of record
      Level: Integer;
      State: THashValue192;
    end;
    FHashTiger: THashTiger;
    function GetLTH(const Buffer: Pointer; const Size: Cardinal): THashValue192;
    function GetITH(const Value1, Value2: THashValue192): THashValue192;
    procedure TestStack;
    function FinalStack: THashValue192;
    procedure ProcessBlock(const Block: Pointer; const Size: Integer);
  protected
    procedure Initialize; override;
    procedure UpdateBlock(const Block: Pointer); override;
    procedure Finalize; override;
    function GetPadBuffer: TBytes; override;
    function CreateHashTiger(const APassCount: Word): THashTiger; virtual;
  public
    constructor Create(const APassCount: Word = 3); virtual;
    destructor Destroy; override;

    class function HashType: THashType; override;
    function HashSize: Cardinal; override;

    property PassCount: Word read FPassCount;

    function BlockSize: Cardinal; override;
  end;

{ THashTigerTree2 }

  THashTigerTree2 = class(THashTigerTree)
  protected
    function CreateHashTiger(const APassCount: Word): THashTiger; override;
  end;

implementation

type
  THashTigerAccess = class(THashTiger)end;

{ THashTigerTree }

constructor THashTigerTree.Create(const APassCount: Word);
begin
  inherited Create;
  FPassCount := APassCount;
  if FPassCount < 1 then FPassCount := 1;
end;

function THashTigerTree.CreateHashTiger(const APassCount: Word): THashTiger;
begin
  Result := THashTiger.Create(APassCount);
end;

class function THashTigerTree.HashType: THashType;
begin
//  Result := htCryptographic;
  Result := THashType.Checksum;
end;

function THashTigerTree.HashSize: Cardinal;
begin
  Result := 24;
end;

function THashTigerTree.BlockSize: Cardinal;
begin
  Result := 1024;
end;

function THashTigerTree.GetLTH(const Buffer: Pointer; const Size: Cardinal): THashValue192;
var
  NullByte: Byte;
  T: THashTigerAccess;
begin
  NullByte := $00;
  T := THashTigerAccess(FHashTiger);
  T.Initialize;
  T.Update(@NullByte, 1);
  T.Update(Buffer, Size);
  T.Finalize;
  Result := T.State;
end;

function THashTigerTree.GetITH(const Value1, Value2: THashValue192): THashValue192;
var
  T: THashTigerAccess;
  OneByte: Byte;
begin
  T := THashTigerAccess(FHashTiger);
  OneByte := $01;
  T.Initialize;
  T.Update(@OneByte, 1);
  T.Update(@Value1, SizeOf(Value1));
  T.Update(@Value2, SizeOf(Value2));
  T.Finalize;
  Result := T.State;
end;

procedure THashTigerTree.TestStack;
var
  L, i: Integer;
begin
  L := Length(Nodes);
  for i := L - 1 downto 1 do
    if Nodes[i-1].Level = Nodes[i].Level then
    begin
      Inc(Nodes[i-1].Level);
      Nodes[i-1].State := GetITH(Nodes[i-1].State, Nodes[i].State);
      Dec(L);
    end else
      Break;
  SetLength(Nodes, L);
end;

function THashTigerTree.FinalStack: THashValue192;
var
  i: Integer;
begin
  for i := High(Nodes) downto 1 do
    Nodes[i-1].State := GetITH(Nodes[i-1].State, Nodes[i].State);
  if Length(Nodes) > 0  then
    Result := Nodes[0].State
  else begin
    Result.A := 0;
    Result.B := 0;
    Result.C := 0;
  end;
  SetLength(Nodes, 0);
end;

procedure THashTigerTree.ProcessBlock(const Block: Pointer; const Size: Integer);
begin
  SetLength(Nodes, Length(Nodes) + 1);
  with Nodes[High(Nodes)] do
  begin
    Level := 0;
    State := GetLTH(Block, Size);
  end;
  TestStack;
end;

procedure THashTigerTree.Initialize;
begin
  inherited;
  if not Assigned(FHashTiger) then
    FHashTiger := CreateHashTiger(FPassCount);
  SetLength(Nodes, 0);
end;

procedure THashTigerTree.UpdateBlock(const Block: Pointer);
begin
  ProcessBlock(Block, 1024);
end;

function THashTigerTree.GetPadBuffer: TBytes;
begin
  Result := nil;
end;

procedure THashTigerTree.Finalize;
var
  FState: THashValue192;
begin
  inherited; // off inherited method;
  if FUsedBuffer > 0 then
    ProcessBlock(@FBlockBuffer[0], FUsedBuffer);
  FState := FinalStack;
  SetValueFromBuffer(@FState, 24);
end;

destructor THashTigerTree.Destroy;
begin
  if Assigned(FHashTiger) then
    FHashTiger.Free;
  inherited;
end;

{ THashTigerTree2 }

function THashTigerTree2.CreateHashTiger(const APassCount: Word): THashTiger;
begin
  Result := THashTiger2.Create(APassCount);
end;

end.
