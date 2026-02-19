{ *********************************************************************** }
{ Copyright (c) 2010-2011 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.Hash.FAQ6;

interface

uses System.Types, System.SysUtils, Rf.Hash;

type

  /// <summary>
  /// FAQ6 Hash Algorithm 32 bit Bob Jenkins (FAQ6) 
  /// </summary>
  THashFAQ6 = class(THash)
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

{ THashFAQ6 }

class function THashFAQ6.HashType: THashType;
begin
  Result := THashType.Checksum;
end;

function THashFAQ6.HashSize: Cardinal;
begin
  Result := 4;
end;

procedure THashFAQ6.Initialize;
begin
  FContext := 0;
end;

procedure THashFAQ6.Update(const Buffer: Pointer; const Size: Cardinal);
var
  i: Integer;
  tmp: DWORD;
begin
  tmp := FContext;
  for i := 0 to Size - 1 do
  begin
    Inc(tmp, PByte(NativeInt(Buffer) + i)^);
    Inc(tmp, tmp shl 10);
    tmp := tmp xor (tmp shr 6);
  end;
  Inc(tmp, tmp shl 3);
  tmp := tmp xor (tmp shr 11);
  Inc(tmp, tmp shl 15);
  FContext := tmp;
end;

procedure THashFAQ6.Finalize;
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
