{ *********************************************************************** }
{ Copyright (c) 2010-2013 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.Hash.BKDR;

interface

uses System.SysUtils, Rf.Hash, Rf.Types;

type

  /// <summary>
  /// BKDR 32 bit
  /// </summary>
  THashBKDR = class(THash)
  private
    FContext: LongWord;
//    FSeed: LongWord;
  protected
    procedure Initialize; override;
    procedure Update(const Buffer: Pointer; const Size: Cardinal); override;
    procedure Finalize; override;
  public
    class function HashType: THashType; override;
    function HashSize: Cardinal; override;
  end;

implementation

{ THashBKDR }

class function THashBKDR.HashType: THashType;
begin
  Result := THashType.Checksum;
end;

function THashBKDR.HashSize: Cardinal;
begin
  Result := 4;
end;

procedure THashBKDR.Initialize;
begin
  FContext := $0;
//  FSeed := 131;
//  FSeed := 131313;
end;

const
  FSeed = 131313;

procedure THashBKDR.Update(const Buffer: Pointer; const Size: Cardinal);
var
  i: Integer;
  tmp: LongWord;
begin
  tmp := FContext;
  for i := 0 to Size - 1 do
    tmp := (tmp * FSeed) + PByteArray(Buffer)^[i];
  FContext := tmp;
end;

procedure THashBKDR.Finalize;
begin
  SetValueFromBuffer(@FContext, 4, True);
end;

end.
