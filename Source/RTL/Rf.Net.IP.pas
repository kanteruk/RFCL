{ *********************************************************************** }
{ Copyright (c) 2016-2017 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.Net.IP;

interface

type

{ TIPAddressV4 }

  TIPAddressV4 = packed record // IPv4 32Bit
  public
    class function Create(const AB1, AB2, AB3, AB4: Byte): TIPAddressV4; overload; static;
    class function Create(const Addr: UInt32): TIPAddressV4; overload; static;
    class function Localhost: TIPAddressV4; static;
  public
  case Integer of
    0: (B1, B2, B3, B4: Byte);
    1: (W1, W2: Word);
    2: (Value: UInt32);
    3: (Addr: UInt32);
  end;
  PIPAddressV4 = ^TIPAddressV4;

{ TIPAddressV6 }

  TIPAddressV6 = packed record // IPv6 128Bit
  public
    class function Localhost: TIPAddressV6; static;
  case Integer of
    0: (Bytes: array [0..15] of Byte);
    1: (Words: array [0..7] of Word);
    2: (DWords: array [0..3] of UInt32);
  end;
  PIPAddressV6 = ^TIPAddressV6;

{ TIPAddress }

  TIPAddress = TIPAddressV4;
  PIPAddress = ^TIPAddress;

implementation

{ TIPAddressV4 }

class function TIPAddressV4.Create(const AB1, AB2, AB3, AB4: Byte): TIPAddressV4;
begin
  with Result do
  begin
    B1 := AB1;
    B2 := AB2;
    B3 := AB3;
    B4 := AB4;
  end;
end;

class function TIPAddressV4.Create(const Addr: UInt32): TIPAddressV4;
begin
  Result.Addr := Addr;
end;

class function TIPAddressV4.Localhost: TIPAddressV4;
begin
  Result := TIPAddressV4.Create(127, 0, 0, 1);
end;

{ TIPAddressV6 }

class function TIPAddressV6.Localhost: TIPAddressV6;
begin
  FillChar(Result, 0, SizeOf(Result));
  Result.Bytes[15] := 1;
end;

end.

