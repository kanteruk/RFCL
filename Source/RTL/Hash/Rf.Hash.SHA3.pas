{ *********************************************************************** }
{ Copyright (c) 2010-2018 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.Hash.SHA3;

interface

uses Rf.SysUtils, Rf.Hash, Rf.Hash.Keccak;

type

  /// <summary>
  /// Secure Hash Algorithm 3 (SHA3)
  /// </summary>
  THashSHA3 = class(THashKeccak)
  protected
    function GetPadBuffer: TBytes; override;
  end;

  THashSHA3_224 = class(THashSHA3)
  public
    constructor Create; reintroduce; virtual;
  end;

  THashSHA3_256 = class(THashSHA3)
  public
    constructor Create; reintroduce; virtual;
  end;

  THashSHA3_384 = class(THashSHA3)
  public
    constructor Create; reintroduce; virtual;
  end;

  THashSHA3_512 = class(THashSHA3)
  public
    constructor Create; reintroduce; virtual;
  end;

implementation

{ THashSHA3 }

function THashSHA3.GetPadBuffer: TBytes;
var
  i, PadLen: Integer;
begin
  PadLen := BlockSize - FUsedBuffer;
  SetLength(Result, PadLen);
  if PadLen = 1 then
		Result[0] := $86
	else if PadLen > 1 then
  begin
    Result[0] := $06;
  	for i := 1 to High(Result) - 1 do
				Result[i] := 0;
		Result[High(Result)] := $80;
	end;
end;

{ THashSHA3_224 }

constructor THashSHA3_224.Create;
begin
  inherited Create(28);
end;

{ THashSHA3_256 }

constructor THashSHA3_256.Create;
begin
  inherited Create(32);
end;

{ THashSHA3_384 }

constructor THashSHA3_384.Create;
begin
  inherited Create(48);
end;

{ THashSHA3_512 }

constructor THashSHA3_512.Create;
begin
  inherited Create(64);
end;

end.
