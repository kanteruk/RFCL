{ *********************************************************************** }
{ Copyright (c) 2010-2011 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.Hash.CRC64;

interface

uses System.SysUtils, Rf.Hash;

type

{
  Name  : CRC-64 (HDLC — ISO 3309)
  Poly  : 0x000000000000001B (Invert: 0xD800000000000000) (Inverted mirror: 0x800000000000000D)
          x64 + x4 + x3 + x + 1
  Init  : 0x0
  Revert: true
  RefOut: false
  XorOut: 0x0
  Check : 0x46A5A9388A5BEFFE ("123456789")
}

  /// <summary>
  /// Cyclic Redundancy Check 64 bit (CRC64)
  /// </summary>
  TCRC64 = class(THash)
  private
    FContext: UInt64;
  private class var
    Table: array[Byte] of UInt64;
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

{ TCRC64 }

class function TCRC64.HashType: THashType;
begin
  Result := THashType.Checksum;
end;

function TCRC64.HashSize: Cardinal;
begin
  Result := 8;
end;

procedure TCRC64.Initialize;
begin
  TableInit;
  FContext := 0;
end;

procedure TCRC64.Update(const Buffer: Pointer; const Size: Cardinal);
var
  i: Integer;
//  tmp: TCRC64;
begin
  for i := 0 to Size - 1 do
    FContext := (FContext shr 8) xor Table[(FContext xor PByteArray(Buffer)[i]) and $FF];
{  tmp := FContext;
  for i := 0 to Size - 1 do
    tmp := (tmp shr 8) xor Table[(tmp xor PByteArray(Buffer)[i]) and $FF];
  FContext := tmp;}
end;

procedure TCRC64.Finalize;
begin
  FContext := FContext xor $0;
  SetValueFromBuffer(@FContext, 8, True);
end;

class procedure TCRC64.TableInit;
var
  c: UInt64;
  i, j: Byte;
begin
  if not TableInitialized then
  begin
    for i := 0 to 255 do
    begin
      c := i;
      for j := 0 to 7 do
        if Odd(c) then
          c := (c shr 1) xor $D800000000000000
        else
          c := (c shr 1);
      Table[i] := c;
    end;
    TableInitialized := True;
  end;
end;

end.
