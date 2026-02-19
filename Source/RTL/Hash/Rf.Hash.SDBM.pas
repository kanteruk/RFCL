{ *********************************************************************** }
{ Copyright (c) 2010-2011 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.Hash.SDBM;

interface

uses System.SysUtils, Rf.Hash, Rf.Types;

type

  /// <summary>
  /// SDBM 32 bit
  /// </summary>
  THashSDBM = class(THash)
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

implementation

{ THashSDBM }

class function THashSDBM.HashType: THashType;
begin
  Result := THashType.Checksum;
end;

function THashSDBM.HashSize: Cardinal;
begin
  Result := 4;
end;

procedure THashSDBM.Initialize;
begin
  FContext := $0;
end;

procedure THashSDBM.Update(const Buffer: Pointer; const Size: Cardinal);
var
  i: Integer;
  tmp: LongWord;
begin
  tmp := FContext;
  for i := 0 to Size - 1 do
    tmp := PByteArray(Buffer)^[i] + (tmp shl 6) + (tmp shl 16) - tmp;
  FContext := tmp;
end;

procedure THashSDBM.Finalize;
begin
  SetValueFromBuffer(@FContext, 4, True);
end;

end.
