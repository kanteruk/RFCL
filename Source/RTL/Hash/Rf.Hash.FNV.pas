{ *********************************************************************** }
{ Copyright (c) 2010-2017 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.Hash.FNV;

{$SCOPEDENUMS ON}

interface

uses System.SysUtils, Rf.Types, Rf.Hash;

type

  TFNVModificationType = (FNV0, FNV1, FNV1a);

  /// <summary>
  /// Fowler–Noll–Vo Hash Algorithm (FNV)
  /// </summary>
  TFNV32 = class(THash)
  private const
    FNV32_PRIME = $01000193;
  private
    FContext: DWORD;
    FModificationType: TFNVModificationType;
  protected
    procedure Initialize; override;
    procedure Update(const Buffer: Pointer; const Size: Cardinal); override;
    procedure Finalize; override;
  public
    constructor Create; overload; virtual;
    constructor Create(const AModificationType: TFNVModificationType); overload; virtual;
    class function HashType: THashType; override;
    function HashSize: Cardinal; override;
    property ModificationType: TFNVModificationType read FModificationType;
  end;

{ TFNV64 }

  TFNV64 = class(THash)
  private
    FContext: UInt64;
    FModificationType: TFNVModificationType;
  protected
    procedure Initialize; override;
    procedure Update(const Buffer: Pointer; const Size: Cardinal); override;
    procedure Finalize; override;
  public
    constructor Create; overload; virtual;
    constructor Create(const AModificationType: TFNVModificationType); overload; virtual;
    class function HashType: THashType; override;
    function HashSize: Cardinal; override;
    property ModificationType: TFNVModificationType read FModificationType;
  end;

implementation

{ TFNV32 }

class function TFNV32.HashType: THashType;
begin
  Result := THashType.Checksum;
end;

function TFNV32.HashSize: Cardinal;
begin
  Result := 4;
end;

constructor TFNV32.Create;
begin
  inherited;
  FModificationType := TFNVModificationType.FNV1a;
end;

constructor TFNV32.Create(const AModificationType: TFNVModificationType);
begin
  inherited Create;
  FModificationType := AModificationType;
end;

procedure TFNV32.Initialize;
begin
  case FModificationType of
    TFNVModificationType.FNV0:
      FContext := 0;
    TFNVModificationType.FNV1, TFNVModificationType.FNV1a:
      FContext := $811C9DC5;
  end;
end;

procedure TFNV32.Update(const Buffer: Pointer; const Size: Cardinal);
var
  i: Integer;
  tmp: DWORD;
begin
  tmp := FContext;
  case FModificationType of
  TFNVModificationType.FNV0, TFNVModificationType.FNV1:
    for i := 0 to Size - 1 do
    begin
      tmp := tmp * FNV32_PRIME;
      tmp := tmp xor PByte(NativeInt(Buffer) + i)^;
    end;
  TFNVModificationType.FNV1a:
    for i := 0 to Size - 1 do
    begin
      tmp := tmp xor PByte(NativeInt(Buffer) + i)^;
      tmp := tmp * FNV32_PRIME;
    end;
  end;
  FContext := tmp;
end;

procedure TFNV32.Finalize;
begin
  with LongRec(FContext) do
  begin
    FValue[0] := Bytes[3];
    FValue[1] := Bytes[2];
    FValue[2] := Bytes[1];
    FValue[3] := Bytes[0];
  end;
end;

const
  FNV64_PRIME = UInt64($0100000001B3);

{ TFNV64 }

class function TFNV64.HashType: THashType;
begin
  Result := THashType.Checksum;
end;

function TFNV64.HashSize: Cardinal;
begin
  Result := 8;
end;

constructor TFNV64.Create;
begin
  inherited;
  FModificationType := TFNVModificationType.FNV1a;
end;

constructor TFNV64.Create(const AModificationType: TFNVModificationType);
begin
  inherited Create;
  FModificationType := AModificationType;
end;

procedure TFNV64.Initialize;
begin
  case FModificationType of
    TFNVModificationType.FNV0:
      FContext := 0;
    TFNVModificationType.FNV1, TFNVModificationType.FNV1a:
      FContext := $CBF29CE484222325;
  end;      
end;

procedure TFNV64.Update(const Buffer: Pointer; const Size: Cardinal);
var
  i: Integer;
  tmp: UInt64;
begin
  tmp := FContext;
  case FModificationType of
  TFNVModificationType.FNV0, TFNVModificationType.FNV1:
    for i := 0 to Size - 1 do
    begin
      tmp := tmp * FNV64_PRIME;
      tmp := tmp xor PByte(NativeInt(Buffer) + i)^;
    end;
  TFNVModificationType.FNV1a:
    for i := 0 to Size - 1 do
    begin
      tmp := tmp xor PByte(NativeInt(Buffer) + i)^;
      tmp := tmp * FNV64_PRIME;
    end;
  end;
  FContext := tmp;
end;

procedure TFNV64.Finalize;
begin
  SetValueFromBuffer(@FContext, 8, True);
end;

end.
