{ *********************************************************************** }
{ Copyright (c) 2010-2017 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }
unit Rf.Hash.BobJenkins;

interface

uses Rf.Types, Rf.Hash;

type

  /// <summary>
  /// BobJenkins Hash (Lookup3)
  /// </summary>
  THashBobJenkins = class(THash)
  private
    FContext: Cardinal;
    FInitValue: Cardinal;
  protected
    procedure Initialize; override;
    procedure Update(const Buffer: Pointer; const Size: Cardinal); override;
    procedure Finalize; override;
    class function HashLittle(const Data: Pointer; Len, InitVal: Cardinal): Cardinal; static; inline;
  public
    class function HashType: THashType; override;
    function HashSize: Cardinal; override;
    constructor Create(const AInitValue: Cardinal = 0); virtual;
  end;

{ THashLookup3 }

  THashLookup3 = THashBobJenkins; // alias

implementation

{ THashBobJenkins }

class function THashBobJenkins.HashType: THashType;
begin
  Result := THashType.Checksum;
end;

function THashBobJenkins.HashSize: Cardinal;
begin
  Result := 4;
end;

constructor THashBobJenkins.Create(const AInitValue: Cardinal = 0);
begin
  FInitValue := AInitValue;
end;

procedure THashBobJenkins.Initialize;
begin
  FContext := FInitValue;
end;

class function THashBobJenkins.HashLittle(const Data: Pointer; Len, InitVal: Cardinal): Cardinal;

  procedure Mix(var a, b, c: Cardinal); inline;
  begin
    Dec(a, c); a := a xor RotateLeft(c, 4); Inc(c, b);
    Dec(b, a); b := b xor RotateLeft(a, 6); Inc(a, c);
    Dec(c, b); c := c xor RotateLeft(b, 8); Inc(b, a);
    Dec(a, c); a := a xor RotateLeft(c,16); Inc(c, b);
    Dec(b, a); b := b xor RotateLeft(a,19); Inc(a, c);
    Dec(c, b); c := c xor RotateLeft(b, 4); Inc(b, a);
  end;

  procedure Final(var a, b, c: Cardinal); inline;
  begin
    c := c xor b; Dec(c, RotateLeft(b,14));
    a := a xor c; Dec(a, RotateLeft(c,11));
    b := b xor a; Dec(b, RotateLeft(a,25));
    c := c xor b; Dec(c, RotateLeft(b,16));
    a := a xor c; Dec(a, RotateLeft(c, 4));
    b := b xor a; Dec(b, RotateLeft(a,14));
    c := c xor b; Dec(c, RotateLeft(b,24));
  end;

{.$POINTERMATH ON}
type
  TByte12 = array[0..11] of Byte;
  PByte12 = ^TByte12;
  TCardinal3 = array[0..2] of Cardinal;
  PCardinal3 = ^TCardinal3;
var
{  pb: PByte;
  pd: PCardinal absolute pb; }
  pb: PByteArray;
  pd: PCardinal3 absolute pb;
  a, b, c: Cardinal;
label
  case_1, case_2, case_3, case_4, case_5, case_6,
  case_7, case_8, case_9, case_10, case_11, case_12;
begin
  a := Cardinal($DEADBEEF) + Len + InitVal;
  b := a;
  c := a;

  pb := Data;

  // 4-byte aligned data
  if (Cardinal(pb) and 3) = 0 then
  begin
    while Len > 12 do
    begin
      Inc(a, pd[0]);
      Inc(b, pd[1]);
      Inc(c, pd[2]);
      Mix(a, b, c);
      Dec(Len, 12);
//      Inc(pd, 3);  // if POINTERMATH is ON
      Inc(PByte(pb), 12);
    end;

    case Len of
      0: begin Result := c; Exit; end;
      1: Inc(a, pd[0] and $FF);
      2: Inc(a, pd[0] and $FFFF);
      3: Inc(a, pd[0] and $FFFFFF);
      4: Inc(a, pd[0]);
      5:
      begin
        Inc(a, pd[0]);
        Inc(b, pd[1] and $FF);
      end;
      6:
      begin
        Inc(a, pd[0]);
        Inc(b, pd[1] and $FFFF);
      end;
      7:
      begin
        Inc(a, pd[0]);
        Inc(b, pd[1] and $FFFFFF);
      end;
      8:
      begin
        Inc(a, pd[0]);
        Inc(b, pd[1]);
      end;
      9:
      begin
        Inc(a, pd[0]);
        Inc(b, pd[1]);
        Inc(c, pd[2] and $FF);
      end;
      10:
      begin
        Inc(a, pd[0]);
        Inc(b, pd[1]);
        Inc(c, pd[2] and $FFFF);
      end;
      11:
      begin
        Inc(a, pd[0]);
        Inc(b, pd[1]);
        Inc(c, pd[2] and $FFFFFF);
      end;
      12:
      begin
        Inc(a, pd[0]);
        Inc(b, pd[1]);
        Inc(c, pd[2]);
      end;
    end;
  end
  else
  begin
    // Ignoring rare case of 2-byte aligned data. This handles all other cases.
    while Len > 12 do
    begin
      Inc(a, pb[0] + pb[1] shl 8 + pb[2] shl 16 + pb[3] shl 24);
      Inc(b, pb[4] + pb[5] shl 8 + pb[6] shl 16 + pb[7] shl 24);
      Inc(c, pb[8] + pb[9] shl 8 + pb[10] shl 16 + pb[11] shl 24);
      Mix(a, b, c);
      Dec(Len, 12);
      //Inc(pb, 12); // if POINTERMATH is ON
      Inc(PByte(pb), 12);
    end;

    case Len of
      0: begin Result := c; Exit; end;
      1: goto case_1;
      2: goto case_2;
      3: goto case_3;
      4: goto case_4;
      5: goto case_5;
      6: goto case_6;
      7: goto case_7;
      8: goto case_8;
      9: goto case_9;
      10: goto case_10;
      11: goto case_11;
      12: goto case_12;
    end;

case_12:
    Inc(c, pb[11] shl 24);
case_11:
    Inc(c, pb[10] shl 16);
case_10:
    Inc(c, pb[9] shl 8);
case_9:
    Inc(c, pb[8]);
case_8:
    Inc(b, pb[7] shl 24);
case_7:
    Inc(b, pb[6] shl 16);
case_6:
    Inc(b, pb[5] shl 8);
case_5:
    Inc(b, pb[4]);
case_4:
    Inc(a, pb[3] shl 24);
case_3:
    Inc(a, pb[2] shl 16);
case_2:
    Inc(a, pb[1] shl 8);
case_1:
    Inc(a, pb[0]);
  end;

  Final(a, b, c);
  Result := c;
{.$POINTERMATH OFF}
end;

procedure THashBobJenkins.Update(const Buffer: Pointer; const Size: Cardinal);
begin
  FContext := HashLittle(Buffer, Size, FContext);
end;

procedure THashBobJenkins.Finalize;
begin
  //SetValueFromBuffer(@FContext, HashSize, True);
  ToBigEndian4(FContext, FValue);
end;

end.
