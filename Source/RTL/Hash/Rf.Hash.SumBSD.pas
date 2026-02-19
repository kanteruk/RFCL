{ *********************************************************************** }
{ Copyright (c) 2010-2011 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.Hash.SumBSD;

interface

uses System.SysUtils, Rf.Hash;

type

  /// <summary>
  /// SumBSD 16 bit
  /// </summary>
  THashSumBSD = class(THash)
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

{ THashSumBSD }

class function THashSumBSD.HashType: THashType;
begin
  Result := THashType.Checksum;
end;

function THashSumBSD.HashSize: Cardinal;
begin
  Result := 2;
end;

procedure THashSumBSD.Initialize;
begin
  FContext := $0;
end;

procedure THashSumBSD.Update(const Buffer: Pointer; const Size: Cardinal);
var
  i: Integer;
  tmp: LongWord;
begin
  tmp := FContext;
  for i := 0 to Size - 1 do
  begin
    tmp := (tmp shr 1) or ((tmp and 1) shl 15);
    Inc(tmp, PByteArray(Buffer)^[i]);
    tmp := tmp and $FFFF;
  end;
  FContext := tmp;
end;

procedure THashSumBSD.Finalize;
begin
  SetValueFromBuffer(@FContext, 2, True);
end;

end.
