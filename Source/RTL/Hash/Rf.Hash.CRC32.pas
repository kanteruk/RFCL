{ *********************************************************************** }
{ Copyright (c) 2010-2011 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.Hash.CRC32;

interface

uses System.Types, System.SysUtils, Rf.Hash;

type

  THashCRC32Abstract = class abstract(THash)
  private
    FContext: DWORD;
  protected
    type
      TTable = array[Byte] of DWORD;
    class procedure TableGenerate(var ATAble: TTable; const APolynomial: DWORD);
  public
    class function HashType: THashType; override;
    function HashSize: Cardinal; override;
  end;

  /// <summary>
  /// Cyclic Redundancy Check 32 bit (CRC32), other names: CRC-32/ISO-HDLC, IEEE, PKZIP
  /// Polynomial: 0x04C11DB7 (reversed: 0xEDB88320) => x^32 + x^26 + x^23 + x^22 + x^16 + x^12 + x^11 + x^10 + x^8 + x^7 + x^5 + x^4 + x^2 + x + 1
  /// Init: 0xFFFFFFFF
  /// Revert: true
  /// RefOut: false
  /// XorOut: 0xFFFFFFFF
  /// Check : 0xCBF43926 ("123456789")
  /// </summary>
  TCRC32 = class(THashCRC32Abstract)
  private class var
    Table: THashCRC32Abstract.TTable;
    TableInitialized: Boolean;
  protected
    procedure Initialize; override;
    procedure Update(const Buffer: Pointer; const Size: Cardinal); override;
    procedure Finalize; override;
  end;

  /// <summary>
  /// Cyclic Redundancy Check 32-bit (CRC-32/Castagnoli)
  /// Polynomial: 0x1EDC6F41 (reversed: 0x82F63B78)
  /// Also known as: CRC-32C, CRC-32/iSCSI, CRC-32/ISCSI
  /// Used in: iSCSI, SCTP, Btrfs, Ext4, NVMe
  /// Hardware accelerated via SSE4.2 CRC32 instruction (Intel Nehalem+, AMD Bulldozer+)
  /// </summary>
  TCRC32C = class(THashCRC32Abstract)
  private class var
    Table: THashCRC32Abstract.TTable;
    TableInitialized: Boolean;
  protected
    procedure Initialize; override;
    procedure Update(const Buffer: Pointer; const Size: Cardinal); override;
    procedure Finalize; override;
  end;

implementation

{ THashCRC32Abstract }

class function THashCRC32Abstract.HashType: THashType;
begin
  Result := THashType.Checksum;
end;

function THashCRC32Abstract.HashSize: Cardinal;
begin
  Result := 4;
end;

class procedure THashCRC32Abstract.TableGenerate(var ATAble: TTable; const APolynomial: DWORD);
var
  c: DWORD;
  i, j: Byte;
begin
  for i := 0 to 255 do
  begin
    c := i;
    for j := 0 to 7 do
      if Odd(c) then
        c := (c shr 1) xor APolynomial
      else
        c := (c shr 1);
    ATable[i] := c;
  end;
end;

{ TCRC32 }

procedure TCRC32.Initialize;
begin
  if not TableInitialized then
  begin
    TableGenerate(Table, $EDB88320);  // Polynomial Reversed
    TableInitialized := True;
  end;
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

{ TCRC32C }

procedure TCRC32C.Initialize;
begin
  if not TableInitialized then
  begin
    TableGenerate(Table, $82F63B78);  // Castagnoli Polynomial Reversed
    TableInitialized := True;
  end;
  FContext := $FFFFFFFF;
end;

procedure TCRC32C.Update(const Buffer: Pointer; const Size: Cardinal);
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

procedure TCRC32C.Finalize;
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

end.
