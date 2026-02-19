{ *********************************************************************** }
{ Copyright (c) 2010-2011 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.Hash.XOR8;

interface

uses System.SysUtils, Rf.Hash;

type

  /// <summary>
  /// Checksum XOR 8 bit (XOR8)
  /// </summary>
  THashXOR8 = class(THash)
  protected
    procedure Initialize; override;
    procedure Update(const Buffer: Pointer; const Size: Cardinal); override;
    procedure Finalize; override;
  public
    class function HashType: THashType; override;
    function HashSize: Cardinal; override;
  end;

implementation

{ THashXOR8 }

class function THashXOR8.HashType: THashType;
begin
  Result := THashType.Checksum;
end;

function THashXOR8.HashSize: Cardinal;
begin
  Result := 1;
end;

procedure THashXOR8.Initialize;
begin
  FValue[0] := 0;
end;

procedure THashXOR8.Update(const Buffer: Pointer; const Size: Cardinal);
var
  i: Integer;
  tmp: Byte;
begin
  tmp := FValue[0];
  for i := 0 to Size - 1 do
    tmp := tmp xor PByteArray(Buffer)[i];
  FValue[0] := tmp;
end;

procedure THashXOR8.Finalize;
begin
end;

end.
