{ *********************************************************************** }
{ Copyright (c) 2020-2026 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.JSONL;

interface

uses
  System.SysUtils, System.Classes, System.JSON;

type
  TJSONLReader = class
  private
    FReader: TStreamReader;
    FLine: string;
  public
    constructor Create(AStrem: TStream); overload;
    constructor Create(const AFileName: TFileName); overload;
    destructor Destroy; override;
    property Reader: TStreamReader read FReader;
    function ReadLine: Boolean; inline;
    property Line: string read FLine; // current readed line after call ReadLine
    function GetJSON(var AJSON: TJSONObject): Boolean; // ReadLine and Parse to JSON
    procedure Rewind;
  end;

  TJSONLWriter = class
  private
    FWriter: TStreamWriter;
    FEncoding: TEncoding;
  public
    constructor Create(AStrem: TStream); overload;
    constructor Create(const AFileName: TFileName; const AAppend: Boolean = False); overload;
    destructor Destroy; override;
    property Writer: TStreamWriter read FWriter;
    procedure WriteLine(const AJSON: string); overload; inline;
    procedure WriteLine(AJSON: TJSONObject); overload;
  end;

implementation

{ TJSONLReader }

constructor TJSONLReader.Create(AStrem: TStream);
begin
  FReader := TStreamReader.Create(AStrem, TEncoding.UTF8)
end;

constructor TJSONLReader.Create(const AFileName: TFileName);
begin
  FReader := TStreamReader.Create(AFileName, TEncoding.UTF8)
end;

destructor TJSONLReader.Destroy;
begin
  FReader.Free;
  inherited;
end;

procedure TJSONLReader.Rewind;
begin
  FReader.Rewind;
  FLine := '';
end;

function TJSONLReader.ReadLine: Boolean;
begin
  Result := not FReader.EndOfStream;
  if Result then
    FLine := FReader.ReadLine;
end;

function TJSONLReader.GetJSON(var AJSON: TJSONObject): Boolean;
begin
  Result := ReadLine;
  if Result then
    AJSON := TJSONObject.ParseJSONValue(FLine) as TJSONObject
  else
    AJSON := nil;
end;

{ TJSONLWriter }

constructor TJSONLWriter.Create(AStrem: TStream);
begin
  FEncoding := TUTF8Encoding.Create(False); // in specification: JSONL - UTF-8 no BOM
  FWriter := TStreamWriter.Create(AStrem, FEncoding);
end;

constructor TJSONLWriter.Create(const AFileName: TFileName; const AAppend: Boolean);
begin
  FEncoding := TUTF8Encoding.Create(False);
  FWriter := TStreamWriter.Create(AFileName, AAppend, FEncoding)
end;

destructor TJSONLWriter.Destroy;
begin
  FWriter.Free;
  FEncoding.Free;
  inherited;
end;

procedure TJSONLWriter.WriteLine(const AJSON: string);
begin
  FWriter.WriteLine(AJSON);
end;

procedure TJSONLWriter.WriteLine(AJSON: TJSONObject);
begin
  WriteLine(AJSON.ToJSON);
end;

end.
