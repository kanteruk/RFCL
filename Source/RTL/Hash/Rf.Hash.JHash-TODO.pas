{ *********************************************************************** }
{ Copyright (c) 2010-2011 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.Hash.JHash;

interface

uses System.SysUtils, Rf.Hash, Rf.Types;

type

  /// <summary>
  /// JHash 32 bit (JHash)
  /// </summary>
  TJHash = class(THash)
  private
    FContext: LongWord;
  protected
    procedure Init; override;
    procedure Update(const Buffer: Pointer; const Size: Cardinal); override;
    procedure Final; override;
  public
    class function HashType: THashType; override;
    function HashSize: Integer; override;
    property Value: LongWord read FContext;
    function ValueAsBytes: TBytes; override;
  end;

implementation

{ TJHash }

class function TJHash.HashType: THashType;
begin
  Result := htChecksum;
end;

function TJHash.HashSize: Integer;
begin
  Result := 4;
end;

procedure TJHash.Init;
begin
  FContext := $4E67C6A7;
end;

procedure TJHash.Update(const Buffer: Pointer; const Size: Cardinal);
var
  i: Integer;
  tmp: LongWord;
begin
  tmp := FContext;
  for i := 0 to Size - 1 do
		tmp := tmp xor ((tmp shl 5) + (tmp shr 2) + PByte(NativeInt(Buffer) + i)^);
	FContext := tmp;
end;

procedure TJHash.Final;
begin
  { do nothing }
end;

function TJHash.ValueAsBytes: TBytes;
begin
  SetLength(Result, 4);
  with LongRec(FContext) do
  begin
    Result[0] := Bytes[3];
    Result[1] := Bytes[2];
    Result[2] := Bytes[1];
    Result[3] := Bytes[0];
  end;
end;

end.
