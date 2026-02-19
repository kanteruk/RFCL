{ *********************************************************************** }
{ Copyright (c) 2010-2011 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.Hash.CRC8Dallas;

interface

uses System.SysUtils, Rf.Hash;

type

{
  Name  : CRC-8
  Poly  : $31  Invert: ($8C) (Invert mirror: $98) // Dallas/ Maxim
          x^8 + x^5 + x^4 + 1
  Init  : $FF
  Revert: false
  RefOut: false
  XorOut: $00
  Check : $F7 ("123456789")
  MaxLen: 15 байт(127 бит) - обнаружение одинарных, двойных, тройных и всех нечетных ошибок
}

  /// <summary>
  /// Cyclic Redundancy Check 8 bit (CRC8)
  /// </summary>
  TCRC8Dallas = class(THash)
  private class var
    Table: array[Byte] of Byte;
    TableInitialized: Boolean;
    class procedure TableInit;
  protected
    procedure Initialize; override;
    procedure Update(const Buffer: Pointer; const Size: Cardinal); override;
    procedure Finalize; override;
  public
    class function HashType: THashType; override;
    function HashSize: Cardinal; override;
  end;

implementation

{ TCRC8Dallas }

class function TCRC8Dallas.HashType: THashType;
begin
  Result := THashType.Checksum;
end;

function TCRC8Dallas.HashSize: Cardinal;
begin
  Result := 1;
end;

procedure TCRC8Dallas.Initialize;
begin
  TableInit;
  FValue[0] := $FF;
end;

procedure TCRC8Dallas.Update(const Buffer: Pointer; const Size: Cardinal);
var
  i: Integer;
  tmp: Byte;
begin
  tmp := FValue[0];
  for i := 0 to Size - 1 do
    tmp := Table[tmp xor PByteArray(Buffer)[i]];
  FValue[0] := tmp
end;

procedure TCRC8Dallas.Finalize;
begin
  FValue[0] := FValue[0] xor $00;
end;

class procedure TCRC8Dallas.TableInit;
var
  c: Byte;
  i, j: Byte;
begin
  if not TableInitialized then
  begin
    for i := 0 to 255 do
    begin
      c := i;
      for j := 0 to 7 do
        if c and $80 <> 0 then
          c := (c shl 1) xor $31
        else
          c := (c shl 1);
      Table[i] := c;
    end;
    TableInitialized := True;
  end;
end;

end.
