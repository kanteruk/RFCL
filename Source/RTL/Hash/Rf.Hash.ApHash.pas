{ *********************************************************************** }
{ Copyright (c) 2010-2013 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.Hash.ApHash;

interface

uses System.SysUtils, Rf.Types, Rf.Hash;

type

  /// <summary>
  /// ApHash 32 bit (ApHash)
  /// </summary>
  TApHash = class(THash)
  private
    FState: DWORD;
    FParity: Boolean;
  protected
    procedure Initialize; override;
    procedure Update(const Buffer: Pointer; const Size: Cardinal); override;
    procedure Finalize; override;
  public
    class function HashType: THashType; override;
    function HashSize: Cardinal; override;
  end;

implementation

{ TApHash }

class function TApHash.HashType: THashType;
begin
  Result := THashType.Checksum;
end;

function TApHash.HashSize: Cardinal;
begin
  Result := 4;
end;

procedure TApHash.Initialize;
begin
  FState := $AAAAAAAA;
  FParity := False;
end;

procedure TApHash.Update(const Buffer: Pointer; const Size: Cardinal);
var
  i: Integer;
  s: DWORD;
  p: Boolean;
  v: PByte;
begin
  s := FState;
  p := FParity;
  v := Buffer;
  for i := 1 to Size do
  begin
    if p then
      S := S xor (not ((S shl 11) xor v^ xor (S shr 5)))
    else
      S := S xor ((S shl 7) xor v^ xor (S shr 3));
    Inc(v);
    P := not P;
  end;
  FState := s;
  FParity := p;
end;

procedure TApHash.Finalize;
begin
  with LongRec(FState) do
  begin
    FValue[0] := Bytes[3];
    FValue[1] := Bytes[2];
    FValue[2] := Bytes[1];
    FValue[3] := Bytes[0];
  end;
end;

end.
