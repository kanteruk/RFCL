{ *********************************************************************** }
{ Copyright (c) 2010-2013 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.Hash.Adler;

interface

uses System.Types, Sysytem.SysUtils, Rf.Hash;

type

{ THashAdler8 }

  THashAdler8 = class(THash)
  private
    FContext: DWORD;
  protected
    procedure Initialize; override;
    procedure Update(const Buffer: Pointer; const Size: Cardinal); override;
    procedure Finalize; override;
  public
    class function HashType: THashType; override;
    function HashSize: Cardinal; override;
  end;

{ THashAdler16 }

  THashAdler16 = class(THash)
  private
    FContext: DWORD;
  protected
    procedure Initialize; override;
    procedure Update(const Buffer: Pointer; const Size: Cardinal); override;
    procedure Finalize; override;
  public
    class function HashType: THashType; override;
    function HashSize: Cardinal; override;
  end;

{ THashAdler32 }

  THashAdler32 = class(THash)
  private
    FContext: DWORD;
  protected
    procedure Initialize; override;
    procedure Update(const Buffer: Pointer; const Size: Cardinal); override;
    procedure Finalize; override;
  public
    class function HashType: THashType; override;
    function HashSize: Cardinal; override;
  end;

implementation

const
  Adler8Base = $0D;
  Adler16Base = $FB;
  Adler32Base = $FFF1;

{ THashAdler8 }

class function THashAdler8.HashType: THashType;
begin
  Result := THashType.Checksum;
end;

function THashAdler8.HashSize: Cardinal;
begin
  Result := 1;
end;

procedure THashAdler8.Initialize;
begin
  FContext := 1;
end;

procedure THashAdler8.Update(const Buffer: Pointer; const Size: Cardinal);
var
  i: Integer;
begin
  with LongRec(FContext) do
    for i := 0 to Size - 1 do
    begin
      Lo := (Lo + PByteArray(Buffer)[i]) mod Adler8Base;
      Hi := (Hi + Lo) mod Adler8Base;
    end;
end;

procedure THashAdler8.Finalize;
begin
  FValue[0] := ((FContext and $F0000) shr 12) or (FContext and $0F);
end;

{ THashAdler16 }

class function THashAdler16.HashType: THashType;
begin
  Result := THashType.Checksum;
end;

function THashAdler16.HashSize: Cardinal;
begin
  Result := 2;
end;

procedure THashAdler16.Initialize;
begin
  FContext := 1;
end;

procedure THashAdler16.Update(const Buffer: Pointer; const Size: Cardinal);
var
  i: Integer;
  v: Int64;
  tmp: LongRec;
begin
  tmp := LongRec(FContext);
  with tmp do
    for i := 0 to Size - 1 do
    begin
{      Lo := (Lo + PByteArray(Buffer)[i]) mod Adler16Base;
      Hi := (Hi + Lo) mod Adler16Base;}

      v := Lo + PByteArray(Buffer)[i];
      while v >= Adler16Base do Dec(v, Adler16Base);
      Lo := v;

      v := Hi + Lo;
      while v >= Adler16Base do Dec(v, Adler16Base);
      Hi := v;
    end;
  FContext := DWORD(tmp);
end;

procedure THashAdler16.Finalize;
var
  FState: Word;
begin
  FState := ((FContext shr 8) and $FF00) or (FContext and $FF);
  with WordRec(FState) do
  begin
    FValue[0] := Bytes[1];
    FValue[1] := Bytes[0];
  end;
end;

{ THashAdler32 }

class function THashAdler32.HashType: THashType;
begin
  Result := THashType.Checksum;
end;

function THashAdler32.HashSize: Cardinal;
begin
  Result := 4;
end;

procedure THashAdler32.Initialize;
begin
  FContext := 1;
end;

procedure THashAdler32.Update(const Buffer: Pointer; const Size: Cardinal);
var
  i: Integer;
  v: Int64;
begin
  with LongRec(FContext) do
    for i := 0 to Size - 1 do
    begin
{        Lo := (Lo + PByteArray(Buffer)[i]) mod Adler32Base;
      Hi := (Hi + Lo) mod Adler32Base;}

      v := Lo + PByteArray(Buffer)[i];
      while v >= Adler32Base do Dec(v, Adler32Base);
      Lo := v;

      v := Hi + Lo;
      while v >= Adler32Base do Dec(v, Adler32Base);
      Hi := v;
    end;
end;

procedure THashAdler32.Finalize;
begin
  with LongRec(FContext) do
  begin
    FValue[0] :=  Bytes[3];
    FValue[1] :=  Bytes[2];
    FValue[2] :=  Bytes[1];
    FValue[3] :=  Bytes[0];
  end;
end;

end.
