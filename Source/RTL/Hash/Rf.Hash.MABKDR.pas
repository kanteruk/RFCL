{ *********************************************************************** }
{ Copyright (c) 2010-2011 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.Hash.MABKDR;

interface

uses System.SysUtils, Rf.Hash, Rf.Types;

type

  /// <summary>
  /// MABKDR 32 bit
  /// </summary>
  THashMABKDR = class(THash)
  private
    FContext: DWORD;
//    FSeed: DWORD;
    FStartIndex: DWORD;
  protected
    procedure Initialize; override;
    procedure Update(const Buffer: Pointer; const Size: Cardinal); override;
    procedure Finalize; override;
  public
    class function HashType: THashType; override;
    function HashSize: Cardinal; override;
  end;

implementation

{ THashMABKDR }

class function THashMABKDR.HashType: THashType;
begin
  Result := THashType.Checksum;
end;

function THashMABKDR.HashSize: Cardinal;
begin
  Result := 4;
end;

procedure THashMABKDR.Initialize;
begin
  FContext := $0;
//  FSeed := 131;
//  FSeed := 131313;
  FStartIndex := 0;
end;

const
  MABKDR_Seed = 131313;
  
procedure THashMABKDR.Update(const Buffer: Pointer; const Size: Cardinal);
var
  i: Integer;
  tmp, st: DWORD;
begin
  st := FStartIndex;
  tmp := FContext;
  for i := 0 to Size - 1 do
    tmp := (tmp * MABKDR_Seed) + PByteArray(Buffer)^[i] + { maBKDR modification here: } st + DWORD(i);
  FContext := tmp;
  Inc(FStartIndex, Size);
end;

procedure THashMABKDR.Finalize;
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
