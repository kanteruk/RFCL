{ *********************************************************************** }
{ Copyright (c) 2010-2011 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.Hash.SumSysV;

interface

uses System.SysUtils, Rf.Hash, Types;

type

  /// <summary>
  /// SumSysV 16 bit (SumSysV) 
  /// </summary>
  THashSumSysV = class(THash)
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

{ THashSumSysV }

class function THashSumSysV.HashType: THashType;
begin
  Result := THashType.Checksum;
end;

function THashSumSysV.HashSize: Cardinal;
begin
  Result := 2;
end;

procedure THashSumSysV.Initialize;
begin
  FContext := $0;
end;

procedure THashSumSysV.Update(const Buffer: Pointer; const Size: Cardinal);
var
  i: Integer;
  tmp: DWORD;
begin
  tmp := FContext;
  for i := 0 to Size - 1 do
    Inc(tmp, PByte(NativeInt(Buffer) + i)^);
  FContext := tmp;
end;

procedure THashSumSysV.Finalize;
var
  r: DWORD;
begin
  r := (FContext and $FFFF) + (((FContext and $FFFFFFFF) shr 16) and $FFFF);
  FContext := (r and $FFFF) + (r shr 16);
  with WordRec(LongRec(FContext).Lo) do
  begin
    FValue[0] := Bytes[1];
    FValue[1] := Bytes[0];
  end;
end;

end.
