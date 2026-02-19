{ *********************************************************************** }
{ Copyright (c) 2010-2011 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.Hash.Rot13;

interface

uses System.SysUtils, Rf.Hash, Rf.Types;

type

  /// <summary>
  /// Rot13 32 bit
  /// </summary>
  THashRot13 = class(THash)
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

{ THashRot13 }

class function THashRot13.HashType: THashType;
begin
  Result := THashType.Checksum;
end;

function THashRot13.HashSize: Cardinal;
begin
  Result := 4;
end;

procedure THashRot13.Initialize;
begin
  FContext := $0;
end;

procedure THashRot13.Update(const Buffer: Pointer; const Size: Cardinal);
var
  i: Integer;
  tmp: DWORD;
begin
  tmp := FContext;
  for i := 0 to Size - 1 do
  begin
    Inc(tmp, PByteArray(Buffer)^[i]);
    Dec(tmp, RotateLeft(tmp, 13));
  end;
  FContext := tmp;
end;

procedure THashRot13.Finalize;
begin
  with LongRec(FContext) do
  begin
    FValue[0] := Bytes[3];
    FValue[1] := Bytes[2];
    FValue[2] := Bytes[1];
    FValue[3] := Bytes[0];
  end;
end;

end.
