{ *********************************************************************** }
{ Copyright (c) 2010-2014 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.Hash.GHash;

interface

uses System.Types, System.SysUtils, Rf.Hash;

type

  /// <summary>
  /// GHash 32 bit (GHash) 
  /// </summary>
  TGHash = class abstract(THash)
  private
    FContext: DWORD;
    //FVer: Byte;
  protected
    procedure Initialize; override;
    procedure Finalize; override;
  public
    class function HashType: THashType; override;
    function HashSize: Cardinal; override;
  end;

{ TGHash3 }

  TGHash3 = class(TGHash)
  protected
    procedure Update(const Buffer: Pointer; const Size: Cardinal); override;
  end;

{ TGHash5 }

  TGHash5 = class(TGHash)
  protected
    procedure Update(const Buffer: Pointer; const Size: Cardinal); override;
  end;


implementation

{ TGHash }

class function TGHash.HashType: THashType;
begin
  Result := THashType.Checksum;
end;

function TGHash.HashSize: Cardinal;
begin
  Result := 4;
end;

procedure TGHash.Initialize;
begin
  FContext := $0;
end;

procedure TGHash.Finalize;
begin
  with LongRec(FContext) do
  begin
    FValue[0] := Bytes[3];
    FValue[1] := Bytes[2];
    FValue[2] := Bytes[1];
    FValue[3] := Bytes[0];
  end;
end;

{ TGHash3 }

procedure TGHash3.Update(const Buffer: Pointer; const Size: Cardinal);
var
  i: Integer;
  tmp: DWORD;
begin
  tmp := FContext;
  for i := 0 to Size - 1 do
    tmp := (tmp shl 3) + tmp + PByte(NativeInt(Buffer) + i)^;
  FContext := tmp;
end;

{ TGHash5 }

procedure TGHash5.Update(const Buffer: Pointer; const Size: Cardinal);
var
  i: Integer;
  tmp: DWORD;
begin
  tmp := FContext;
  for i := 0 to Size - 1 do
    tmp := (tmp shl 5) + tmp + PByte(NativeInt(Buffer) + i)^;
  FContext := tmp;
end;

end.
