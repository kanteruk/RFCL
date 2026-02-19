{ *********************************************************************** }
{ Copyright (c) 2010-2011 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.Hash.RsHash;

interface

uses System.SysUtils, Rf.Hash, Rf.Types;

type

  /// <summary>
  /// RsHash 32 bit (RsHash) 
  /// </summary>
  TRSHash = class(THash)
  private
    FState: DWORD;
    Fva: DWORD;
  protected
    procedure Initialize; override;
    procedure Update(const Buffer: Pointer; const Size: Cardinal); override;
    procedure Finalize; override;
  public
    class function HashType: THashType; override;
    function HashSize: Cardinal; override;
  end;

implementation

{ TRSHash }

class function TRSHash.HashType: THashType;
begin
  Result := THashType.Checksum;
end;

function TRSHash.HashSize: Cardinal;
begin
  Result := 4;
end;

procedure TRSHash.Initialize;
begin
  FState := 0;
  Fva := $0000F8C9;
end;

procedure TRSHash.Update(const Buffer: Pointer; const Size: Cardinal);
var
  i: Integer;
  tmp, tmpa: DWORD;
begin
  tmp := FState;
  tmpa := Fva;
  for i := 0 to Size - 1 do
  begin
    tmp := tmp * tmpa + PByte(NativeInt(Buffer) + i)^;
    tmpa := tmpa * $0005C6B7;
  end;
  FState := tmp;
  Fva := tmpa;
end;

procedure TRSHash.Finalize;
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
