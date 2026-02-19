{ *********************************************************************** }
{ Copyright (c) 2010-2011 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.Hash.CRC16CCITT;

interface

uses System.SysUtils, Rf.Hash;

type

{
  Name  : CRC-16 CCITT
  Poly  : $1021 (Invert: $8408) (Invert miror: $8810)
          x^16 + x^12 + x^5 + 1
  Init  : 0xFFFF
  Revert: false
  RefOut: false
  XorOut: 0x0000
  Check : 0x29B1 ("123456789")
}

  /// <summary>
  /// Cyclic Redundancy Check CCITT 16 bit (CRC16CCITT)
  /// </summary>
  TCRC16CCITT = class(THash)
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

{ TCRC16CCITT }

class function TCRC16CCITT.HashType: THashType;
begin
  Result := THashType.Checksum;
end;

function TCRC16CCITT.HashSize: Cardinal;
begin
  Result := 2;
end;

procedure TCRC16CCITT.Initialize;
begin
  TableInit;
  FContext := $FFFF;
end;

procedure TCRC16CCITT.Update(const Buffer: Pointer; const Size: Cardinal);
var
  i: Integer;
  tmp: Word;
begin
{  for i := 0 to Size - 1 do
    Context := (Context shl 8) xor CRC16CCITTTable[((Context shr 8) xor PByteArray(Buffer)[i]) and $FF];}
  tmp := FContext;
  for i := 0 to Size - 1 do
    tmp := (tmp shl 8) xor Table[((tmp shr 8) xor PByteArray(Buffer)[i]) and $FF];
  FContext := tmp;
end;

procedure TCRC16CCITT.Finalize;
begin
  FContext := FContext xor $0000;
  with WordRec(FContext) do
  begin
    FValue[0] := Bytes[1];
    FValue[1] := Bytes[0];
  end;
end;

class procedure TCRC16CCITT.TableInit;
var
  c: Word;
  i, j: Byte;
begin
  if not TableInitialized then
  begin
    for i := 0 to 255 do
    begin
      c := i shl 8;
      for j := 0 to 7 do
        if c and $8000 <> 0 then
          c := (c shl 1) xor $1021
        else
          c := (c shl 1);
      Table[i] := c;
    end;
    TableInitialized := True;
  end;
end;

end.
