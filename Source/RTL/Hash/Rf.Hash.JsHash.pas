{ *********************************************************************** }
{ Copyright (c) 2010-2011 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.Hash.JsHash;

interface

uses System.SysUtils, Rf.Hash, Rf.Types;

type

  /// <summary>
  /// JsHash 32 bit (JsHash)
  /// </summary>
  TJsHash = class(THash)
  private
    FState: DWORD;
  protected
    procedure Initialize; override;
    procedure Update(const Buffer: Pointer; const Size: Cardinal); override;
    procedure Finalize; override;
  public
    class function HashType: THashType; override;
    function HashSize: Cardinal; override;
  end;

implementation

{ TJsHash }

class function TJsHash.HashType: THashType;
begin
  Result := THashType.Checksum;
end;

function TJsHash.HashSize: Cardinal;
begin
  Result := 4;
end;

procedure TJsHash.Initialize;
begin
  FState := $4E67C6A7;
end;

procedure TJsHash.Update(const Buffer: Pointer; const Size: Cardinal);
var
  i: Integer;
  tmp: DWORD;
begin
  tmp := FState;
  for i := 0 to Size - 1 do
    tmp := tmp xor ((tmp shl 5) + (tmp shr 2) + PByte(NativeInt(Buffer) + i)^);
  FState := tmp;
end;

procedure TJsHash.Finalize;
begin
  with LongRec(FState) do
  begin
    FValue[0] := Bytes[3];
    FValue[1] := Bytes[2];
    FValue[2] := Bytes[1];
    FValue[3] := Bytes[0];
  end;
end;

end.
