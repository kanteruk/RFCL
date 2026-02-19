{ *********************************************************************** }
{ Copyright (c) 2010-2011 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.Hash.CRC32;

interface

uses System.Types, System.SysUtils, Rf.Hash;

type

{
  Name  : CRC-32
  Poly  : 0x04C11DB7 (Invert: 0xEDB88320)
          x^32 + x^26 + x^23 + x^22 + x^16 + x^12 + x^11 + x^10 +
          x^8 + x^7 + x^5 + x^4 + x^2 + x + 1
  Init  : 0xFFFFFFFF
  Revert: true
  RefOut: false
  XorOut: 0xFFFFFFFF
  Check : 0xCBF43926 ("123456789")
  MaxLen: 268 435 455 байт (2 147 483 647 бит) - обнаружение одинарных, двойных, пакетных и всех нечетных ошибок
}

  /// <summary>
  /// Cyclic Redundancy Check 32 bit (CRC32)
  /// </summary>
  TCRC32 = class(THash)
  private
    FContext: DWORD;
  private class var
    Table: array[Byte] of DWORD;
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

{ TCRC32 }

class function TCRC32.HashType: THashType;
begin
  Result := THashType.Checksum;
end;

function TCRC32.HashSize: Cardinal;
begin
  Result := 4;
end;

procedure TCRC32.Initialize;
begin
  TableInit;
  FContext := $FFFFFFFF;
end;

procedure TCRC32.Update(const Buffer: Pointer; const Size: Cardinal);
var
  i: Integer;
  tmp: Cardinal;
begin
{  for i := 0 to Size - 1 do
    Context := (Context shr 8) xor Table[(Context xor PByteArray(Buffer)[i]) and $FF];}
  tmp := FContext;
  for i := 0 to Size - 1 do
    tmp := (tmp shr 8) xor Table[(tmp xor PByteArray(Buffer)[i]) and $FF];
  FContext := tmp;
end;

procedure TCRC32.Finalize;
begin
  FContext := FContext xor $FFFFFFFF;
  with LongRec(FContext) do
  begin
    FValue[0] := Bytes[3];
    FValue[1] := Bytes[2];
    FValue[2] := Bytes[1];
    FValue[3] := Bytes[0];
  end;
end;

class procedure TCRC32.TableInit;
var
  c: DWORD;
  i, j: Byte;
begin
  if not TableInitialized then
  begin
    for i := 0 to 255 do
    begin
      c := i;
      for j := 0 to 7 do
        if Odd(c) then
          c := (c shr 1) xor $EDB88320
        else
          c := (c shr 1);
      Table[i] := c;
    end;
    TableInitialized := True;
  end;
end;

end.
