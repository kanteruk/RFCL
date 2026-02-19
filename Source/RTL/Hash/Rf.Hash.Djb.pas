{ *********************************************************************** }
{ Copyright (c) 2010-2011 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.Hash.Djb;

interface

uses System.SysUtils, Rf.Hash, Rf.Types;

type

  /// <summary>
  /// Djb 32 bit
  /// </summary>
  TDjbHash = class(THash)
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

{ TDjbHash }

class function TDjbHash.HashType: THashType;
begin
  Result := THashType.Checksum;
end;

function TDjbHash.HashSize: Cardinal;
begin
  Result := 4;
end;

procedure TDjbHash.Initialize;
begin
  FContext := 5381;
end;

procedure TDjbHash.Update(const Buffer: Pointer; const Size: Cardinal);
var
  i: Integer;
  tmp: DWORD;
begin
  tmp := FContext;
  for i := 0 to Size - 1 do
    tmp := ((tmp shl 5) + tmp) + PByteArray(Buffer)^[i];
  FContext := tmp;
end;

procedure TDjbHash.Finalize;
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
