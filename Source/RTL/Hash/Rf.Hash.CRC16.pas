{ *********************************************************************** }
{ Copyright (c) 2010-2011 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.Hash.CRC16;

interface

uses System.SysUtils, Rf.Hash;

type

{
  Name  : CRC-16
  Poly  : 0x8005 (Invert: 0xA001) (Invert mirror: $C002)
          x^16 + x^15 + x^2 + 1
  Init  : 0x0000
  Revert: true
  RefOut: true
  XorOut: 0x0000
  Check : 0xBB3D ("123456789")
}

  /// <summary>
  /// Cyclic Redundancy Check 16 bit (CRC16)
  /// </summary>
  TCRC16 = class(THash)
  private
    FContext: Word;
  private class var
    Table: array[Byte] of Word;
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

{ TCRC16 }

class function TCRC16.HashType: THashType;
begin
  Result := THashType.Checksum;
end;

function TCRC16.HashSize: Cardinal;
begin
  Result := 2;
end;

procedure TCRC16.Initialize;
begin
  TableInit;
  FContext := $0000;
end;

procedure TCRC16.Update(const Buffer: Pointer; const Size: Cardinal);
var
  i: Integer;
  tmp: Word;
begin
{  for i := 0 to Size - 1 do
    Context := (Context shr 8) xor Table[(Context xor PByteArray(Buffer)[i]) and $FF];}
  tmp := FContext;
  for i := 0 to Size - 1 do
    tmp := (tmp shr 8) xor Table[(tmp xor PByteArray(Buffer)[i]) and $FF];
  FContext := tmp;
end;

procedure TCRC16.Finalize;
begin
  FContext := FContext xor $0000;
  with WordRec(FContext) do
  begin
    FValue[0] := Bytes[1];
    FValue[1] := Bytes[0];
  end;
end;

class procedure TCRC16.TableInit;
var
  c: Word;
  i, j: Byte;
begin
  if not TableInitialized then
  begin
    for i := 0 to 255 do
    begin
      c := i;
      for j := 0 to 7 do
        if Odd(c) then
          c := (c shr 1) xor $A001
        else
          c := (c shr 1);
      Table[i] := c;
    end;
    TableInitialized := True;
  end;
end;

end.
