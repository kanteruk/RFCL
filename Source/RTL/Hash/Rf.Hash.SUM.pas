{ *********************************************************************** }
{ Copyright (c) 2010-2017 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.Hash.SUM;

interface

uses System.SysUtils, Rf.Hash;

type

  /// <summary>
  /// Checksum (SUM)
  /// </summary>
  THashSUM8 = class(THash)
  protected
    procedure Initialize; override;
    procedure Update(const Buffer: Pointer; const Size: Cardinal); override;
    procedure Finalize; override;
  public
    class function HashType: THashType; override;
    function HashSize: Cardinal; override;
  end;

{ THashSUM16 }

  THashSUM16 = class(THash)
  private
    FContext: Word;
  protected
    procedure Initialize; override;
    procedure Update(const Buffer: Pointer; const Size: Cardinal); override;
    procedure Finalize; override;
  public
    class function HashType: THashType; override;
    function HashSize: Cardinal; override;
  end;

{ THashSUM24 }

  THashSUM24 = class(THash)
  private
    FContext: LongWord;
  protected
    procedure Initialize; override;
    procedure Update(const Buffer: Pointer; const Size: Cardinal); override;
    procedure Finalize; override;
  public
    class function HashType: THashType; override;
    function HashSize: Cardinal; override;
  end;

{ THashSUM32 }

  THashSUM32 = class(THash)
  private
    FContext: LongWord;
  protected
    procedure Initialize; override;
    procedure Update(const Buffer: Pointer; const Size: Cardinal); override;
    procedure Finalize; override;
  public
    class function HashType: THashType; override;
    function HashSize: Cardinal; override;
  end;

{ THashSUM64 }

  THashSUM64 = class(THash)
  private
    FContext: UInt64;
  protected
    procedure Initialize; override;
    procedure Update(const Buffer: Pointer; const Size: Cardinal); override;
    procedure Finalize; override;
  public
    class function HashType: THashType; override;
    function HashSize: Cardinal; override;
  end;

implementation

{ THashSUM8 }

class function THashSUM8.HashType: THashType;
begin
  Result := THashType.Checksum;
end;

function THashSUM8.HashSize: Cardinal;
begin
  Result := 1;
end;

procedure THashSUM8.Initialize;
begin
  FValue[0] := 0;
end;

procedure THashSUM8.Update(const Buffer: Pointer; const Size: Cardinal);
var
  i: Integer;
  tmp: Byte; // for faster calc
begin
  tmp := FValue[0];
  for i := 0 to Size - 1 do
    Inc(tmp, PByteArray(Buffer)[i]);
  FValue[0] := tmp;
end;

procedure THashSUM8.Finalize;
begin
end;

{ THashSUM16 }

class function THashSUM16.HashType: THashType;
begin
  Result := THashType.Checksum;
end;

function THashSUM16.HashSize: Cardinal;
begin
  Result := 2;
end;

procedure THashSUM16.Initialize;
begin
  FContext := 0;
end;

procedure THashSUM16.Update(const Buffer: Pointer; const Size: Cardinal);
var
  i: Integer;
  tmp: Word;
begin
  tmp := FContext;
  for i := 0 to Size - 1 do
    Inc(tmp, PByteArray(Buffer)[i]);
  FContext := tmp;
end;

procedure THashSUM16.Finalize;
begin
  with WordRec(FContext) do
  begin
    FValue[0] := Bytes[1];
    FValue[1] := Bytes[0];
  end;
end;

{ THashSUM24 }

class function THashSUM24.HashType: THashType;
begin
  Result := THashType.Checksum;
end;

function THashSUM24.HashSize: Cardinal;
begin
  Result := 3;
end;

procedure THashSUM24.Initialize;
begin
  FContext := 0;
end;

procedure THashSUM24.Update(const Buffer: Pointer; const Size: Cardinal);
var
  i: Integer;
  tmp: LongWord;
begin
  tmp := FContext;
  for i := 0 to Size - 1 do
    Inc(tmp, PByteArray(Buffer)[i]);
  FContext := tmp;
end;

procedure THashSUM24.Finalize;
begin
  FValue[0] := FContext shr 16;
  FValue[1] := FContext shr 8;
  FValue[2] := FContext and $FF;
//  SetValueFromBuffer(@FContext, 3, True);
end;

{ THashSUM32 }

class function THashSUM32.HashType: THashType;
begin
  Result := THashType.Checksum;
end;

function THashSUM32.HashSize: Cardinal;
begin
  Result := 4;
end;

procedure THashSUM32.Initialize;
begin
  FContext := 0;
end;

procedure THashSUM32.Update(const Buffer: Pointer; const Size: Cardinal);
var
  i: Integer;
  tmp: LongWord;
begin
  tmp := FContext;
  for i := 0 to Size - 1 do
    Inc(tmp, PByteArray(Buffer)[i]);
  FContext := tmp;
end;

procedure THashSUM32.Finalize;
begin
  SetValueFromBuffer(@FContext, 4, True);
end;

{ THashSUM64 }

class function THashSUM64.HashType: THashType;
begin
  Result := THashType.Checksum;
end;

function THashSUM64.HashSize: Cardinal;
begin
  Result := 8;
end;

procedure THashSUM64.Initialize;
begin
  FContext := 0;
end;

procedure THashSUM64.Update(const Buffer: Pointer; const Size: Cardinal);
var
  i: Integer;
  tmp: UInt64;
begin
  tmp := FContext;
  for i := 0 to Size - 1 do
    Inc(tmp, PByteArray(Buffer)[i]);
  FContext := tmp;
end;

procedure THashSUM64.Finalize;
begin
  SetValueFromBuffer(@FContext, 8, True);
end;

end.
