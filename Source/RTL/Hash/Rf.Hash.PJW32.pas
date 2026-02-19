{ *********************************************************************** }
{ Copyright (c) 2010-2011 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.Hash.PJW32;

interface

uses System.Types, System.SysUtils, Rf.Hash;

type

  /// <summary>
  /// Peter J. Weinberger Hash Algorithm 32 bit (PJW32)
  /// </summary>
  THashPJW32 = class(THash)
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

{ THashPJW32 }

class function THashPJW32.HashType: THashType;
begin
  Result := THashType.Checksum;
end;

function THashPJW32.HashSize: Cardinal;
begin
  Result := 4;
end;

procedure THashPJW32.Initialize;
begin
  FContext := 0;
end;

procedure THashPJW32.Update(const Buffer: Pointer; const Size: Cardinal);
var
  i: Integer;
  tmp, tst: DWORD;
begin
  tmp := FContext;
  for i := 0 to Size - 1 do
  begin
    tmp := (tmp shl 4) + PByte(NativeInt(Buffer) + i)^;
    tst := tmp and $F0000000;
    if tst <> 0 then
      tmp := (tmp xor (tst shr 28)) and $0FFFFFFF;
  end;
  FContext := tmp;
end;

procedure THashPJW32.Finalize;
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
