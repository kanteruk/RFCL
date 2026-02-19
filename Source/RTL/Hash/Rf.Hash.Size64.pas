{ *********************************************************************** }
{ Copyright (c) 2010-2017 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.Hash.Size64;

interface

uses Rf.Hash;

type

  /// <summary>
  /// Size64 64 Bit (Size64)
  /// </summary>
  THashSize64 = class(THash)
  private
    FContext: UInt64;
  protected
    procedure Initialize; override;
    procedure Update(const Buffer: Pointer; const Size: Cardinal); override;
    procedure Finalize; override;
  public
    class function HashType: THashType; override;
    function HashSize: Cardinal; override;
  end;

implementation

{ THashSize64 }

class function THashSize64.HashType: THashType;
begin
  Result := THashType.Checksum;
end;

function THashSize64.HashSize: Cardinal;
begin
  Result := 8;
end;

procedure THashSize64.Initialize;
begin
  FContext := $0;
end;

procedure THashSize64.Update(const Buffer: Pointer; const Size: Cardinal);
begin
  Inc(FContext, Size);
end;

procedure THashSize64.Finalize;
begin
  SetValueFromBuffer(@FContext, 8, True);
end;

end.
