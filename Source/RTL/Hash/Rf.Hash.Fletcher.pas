{ *********************************************************************** }
{ Copyright (c) 2010-2014 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.Hash.Fletcher;

interface

uses System.SysUtils, Rf.Hash;

type

  /// <summary>
  /// Fletcher
  /// </summary>
  TFletcher8 = class(THash)
  private
    FModul: Byte;
    FValue1, FValue2: Byte;
  protected
    procedure Initialize; override;
    procedure Update(const Buffer: Pointer; const Size: Cardinal); override;
    procedure Finalize; override;
  public
    constructor Create; virtual;
    class function HashType: THashType; override;
    function HashSize: Cardinal; override;
  end;

{ TFletcher16 }

  TFletcher16 = class(THash)
  private
    FModul: Byte;
    FValue1, FValue2: Byte;
  protected
    procedure Initialize; override;
    procedure Update(const Buffer: Pointer; const Size: Cardinal); override;
    procedure Finalize; override;
  public
    constructor Create; virtual;
    class function HashType: THashType; override;
    function HashSize: Cardinal; override;
  end;

{ TFletcher32 }

  TFletcher32 = class(THash)
  private
    FModul: Word;
    FValue1, FValue2: Word;
  protected
    procedure Initialize; override;
    procedure Update(const Buffer: Pointer; const Size: Cardinal); override;
    procedure Finalize; override;
  public
    constructor Create; virtual;
    class function HashType: THashType; override;
    function HashSize: Cardinal; override;
  end;

implementation

{ TFletcher8 }

class function TFletcher8.HashType: THashType;
begin
  Result := THashType.Checksum;
end;

function TFletcher8.HashSize: Cardinal;
begin
  Result := 1;
end;

constructor TFletcher8.Create;
begin
  inherited;
  FModul := $F;
end;

procedure TFletcher8.Initialize;
begin
  FValue1 := 0;
  FValue2 := 0;
end;

procedure TFletcher8.Update(const Buffer: Pointer; const Size: Cardinal);
var
  i: Integer;
  s1, s2: Byte;
begin
  s1 := FValue1;
  s2 := FValue2;
  for i := 0 to Size - 1 do
  begin
    s1 := (s1 + PByteArray(Buffer)^[i]) mod FModul;
    s2 := (s2 + s1) mod FModul;
  end;
  FValue1 := s1;
  FValue2 := s2;
end;

procedure TFletcher8.Finalize;
begin
  FValue[0] := (FValue2 shl 4) or FValue1;
end;

{ TFletcher16 }

class function TFletcher16.HashType: THashType;
begin
  Result := THashType.Checksum;
end;

function TFletcher16.HashSize: Cardinal;
begin
  Result := 2;
end;

constructor TFletcher16.Create;
begin
  inherited;
  FModul := $FF;
end;

procedure TFletcher16.Initialize;
begin
  FValue1 := 0;
  FValue2 := 0;
end;

procedure TFletcher16.Update(const Buffer: Pointer; const Size: Cardinal);
var
  i: Integer;
  s1, s2: Byte;
begin
  s1 := FValue1;
  s2 := FValue2;
  for i := 0 to Size - 1 do
  begin
    s1 := (s1 + PByteArray(Buffer)^[i]) mod FModul;
    s2 := (s2 + s1) mod FModul;
  end;
  FValue1 := s1;
  FValue2 := s2;
end;

procedure TFletcher16.Finalize;
begin
  FValue[0] := FValue2;
  FValue[1] := FValue1;
end;

{ TFletcher32 }

class function TFletcher32.HashType: THashType;
begin
  Result := THashType.Checksum;
end;

function TFletcher32.HashSize: Cardinal;
begin
  Result := 4;
end;

constructor TFletcher32.Create;
begin
  inherited;
  FModul := $FFFF;
end;

procedure TFletcher32.Initialize;
begin
  FValue1 := 0;
  FValue2 := 0;
end;

procedure TFletcher32.Update(const Buffer: Pointer; const Size: Cardinal);
var
  i: Integer;
  s1, s2: Word;
begin
  s1 := FValue1;
  s2 := FValue2;
  for i := 0 to Size - 1 do
  begin
    s1 := (s1 + PByteArray(Buffer)^[i]) mod FModul;
    s2 := (s2 + s1) mod FModul;
  end;
  FValue1 := s1;
  FValue2 := s2;
end;

procedure TFletcher32.Finalize;
begin
  FValue[0] := FValue2 shr 8;
  FValue[1] := FValue2 and $FF;
  FValue[2] := FValue1 shr 8;
  FValue[3] := FValue1 and $FF;
end;

end.
