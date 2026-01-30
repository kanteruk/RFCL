{ *********************************************************************** }
{ Copyright (c) 2010-2024 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.CSV.Reader;

interface

uses
  System.SysUtils, System.Classes, System.Generics.Collections;

type
  /// <summary>
  ///   class for read csv file
  ///
  ///  R := TCSVReader.Create(AFileName, TEncoding.UTF8, #9, '"');
  ///  try
  ///    while not R.EOF do
  ///    begin
  ///      R.ReadRow;
  ///      for var i := 0 to R.Columns.Count - 1 do
  ///        PrintColum(R.Columns[i]);
  ///   end;
  ///  finally
  ///    R.Free;
  ///  end
  /// </summary>
  TCSVReader = class(TObject)
  private const
    BUFFER_SIZE = 64 * 1024;
  private
    FFileName: TFileName;
    FStreamReader: TStreamReader;
    FColumns: TList<string>;
    FDelimChar: Char;
    FQuoteChar: Char;
    function GetEOF: Boolean;
    function GetFileSize: Int64;
    function GetPosition: Int64;
  public
    constructor Create(const AFileName: TFileName; const AEncoding: TEncoding; const ADelimChar, AQuoteChar: Char); virtual;
    destructor Destroy; override;

    property FileName: TFileName read FFileName;
    property DelimChar: Char read FDelimChar;
    property QuoteChar: Char read FQuoteChar;

    property EOF: Boolean read GetEOF;
    property FileSize: Int64 read GetFileSize;
    property Position: Int64 read GetPosition;

    procedure ReadRow;
    property Columns: TList<string> read FColumns;
    function ColumnDef(const AIndex: Integer; const ADefault: string): string;
  end;

implementation

type
  TStreamReaderEx = class(TStreamReader)
  public
    FDelimChar: Char;
    FQuoteChar: Char;
    //function ReadLine: string; override;
    procedure ReadRow(var AColumns: TList<string>);
  end;

{ TStreamReaderEx }

{function TStreamReaderEx.ReadLine: string;
var
  NewLineIndex: Integer;
  PostNewLineIndex: Integer;
  LChar: Char;
  FEncoding: TEncoding;
  FQuoteCounter: Integer;
begin
FEncoding := CurrentEncoding;
FQuoteCounter := 0;

  Result := '';
  if FBufferedData = nil then
    Exit;
  NewLineIndex := 0;
  PostNewLineIndex := 0;

  while True do
  begin
    if (NewLineIndex + 2 > FBufferedData.Length) and (not FNoDataInStream) then
      FillBuffer(FEncoding);

    if NewLineIndex >= FBufferedData.Length then
    begin
      if FNoDataInStream then
      begin
        PostNewLineIndex := NewLineIndex;
        Break;
      end
      else
      begin
        FillBuffer(FEncoding);
        if FBufferedData.Length = 0 then
          Break;
      end;
    end;
    LChar := FBufferedData.Chars[NewLineIndex];
    if (FQuoteChar <> #0) and (LChar = FQuoteChar) then // test quote
      Inc(FQuoteCounter)
    else if LChar = #10 then
    begin
      if FQuoteCounter mod 2 = 0 then // if LF marker in quoted value skip it as LineBreak
      begin
        PostNewLineIndex := NewLineIndex + 1;
        Break;
      end;
    end
    else if LChar = #13 then
    begin
      if FQuoteCounter mod 2 = 0 then // if LF marker in quoted value skip it as LineBreak
      begin
        if (NewLineIndex + 1 < FBufferedData.Length) and (FBufferedData.Chars[NewLineIndex + 1] = #10) then
          PostNewLineIndex := NewLineIndex + 2
        else
          PostNewLineIndex := NewLineIndex + 1;
        Break;
      end;
    end;

    Inc(NewLineIndex);
  end;

  FBufferedData.MoveString(NewLineIndex, PostNewLineIndex, Result);
  FBufferedData.TrimBuffer;
end;}

procedure TStreamReaderEx.ReadRow(var AColumns: TList<string>);
var
  NewLineIndex: Integer;
  PostNewLineIndex: Integer;
  LChar: Char;
  FEncoding: TEncoding;
  FQuoteCounter: Integer;
  LCol: string;
  LastQuoted: Boolean;
begin
FEncoding := CurrentEncoding;
FQuoteCounter := 0;
LastQuoted := False;

  AColumns.Clear;
  if FBufferedData = nil then
    Exit;
  NewLineIndex := 0;
  PostNewLineIndex := 0;

  while True do
  begin
    if (NewLineIndex + 2 > FBufferedData.Length) and (not FNoDataInStream) then
      FillBuffer(FEncoding);

    if NewLineIndex >= FBufferedData.Length then
    begin
      if FNoDataInStream then
      begin
        PostNewLineIndex := NewLineIndex;
        Break;
      end
      else
      begin
        FillBuffer(FEncoding);
        if FBufferedData.Length = 0 then
          Break;
      end;
    end;
    LChar := FBufferedData.Chars[NewLineIndex];
    
    if FQuoteChar <> #0 then  // test quote
    begin
      if LChar = FQuoteChar then
      begin
        if LastQuoted then
        begin
          LastQuoted := False;
          Inc(FQuoteCounter, 2);
        end
        else 
          LastQuoted := True;
      end
      else begin
        if LastQuoted then
        begin
          LastQuoted := false;
          // The quoted char is not doubled, should we put in the resulting string?
          Inc(FQuoteCounter);
        end;
      end;
    
(*      if LChar = FQuoteChar then 
      begin
        if (NewLineIndex > 0) and (FBufferedData.Chars[NewLineIndex-1] = FQuoteChar) then // if prev quote - so skip double quted
        
        else  
          Inc(FQuoteCounter);

        if FQuoteCounter = 2 then
        begin
          {PostNewLineIndex := NewLineIndex + 1;
          FBufferedData.MoveString(NewLineIndex+1, PostNewLineIndex, LCol);
          AColumns.Add(LCol.DeQuotedString(FQuoteChar));
          NewLineIndex := -1;}
        end     
      end    *)
    end;
    
    if (LChar = FDelimChar) and (FQuoteCounter mod 2 = 0) then
    begin
      PostNewLineIndex := NewLineIndex + 1;
      FBufferedData.MoveString(NewLineIndex, PostNewLineIndex, LCol);
      NewLineIndex := -1;
      if FQuoteCounter > 0 then
      begin
        LCol := LCol.DeQuotedString(FQuoteChar);
        FQuoteCounter := 0;
      end;
      AColumns.Add(LCol);
    end
    else if LChar = #10 then
    begin
      if FQuoteCounter mod 2 = 0 then // if LF marker in quoted value skip it as LineBreak
      begin
        PostNewLineIndex := NewLineIndex + 1;
        Break;
      end;
    end
    else if LChar = #13 then
    begin
      if FQuoteCounter mod 2 = 0 then // if LF marker in quoted value skip it as LineBreak
      begin
        if (NewLineIndex + 1 < FBufferedData.Length) and (FBufferedData.Chars[NewLineIndex + 1] = #10) then
          PostNewLineIndex := NewLineIndex + 2
        else
          PostNewLineIndex := NewLineIndex + 1;
        Break;
      end;
    end;

    Inc(NewLineIndex);
  end;


  FBufferedData.MoveString(NewLineIndex, PostNewLineIndex, LCol);
  if not LCol.IsEmpty then
  begin
    if FQuoteCounter > 0 then
    begin
      LCol := LCol.DeQuotedString(FQuoteChar);
      //FQuoteCounter := 0;
    end;
    AColumns.Add(LCol);
  end;

  FBufferedData.TrimBuffer;
end;

{ TCSVReader }

constructor TCSVReader.Create(const AFileName: TFileName; const AEncoding: TEncoding; const ADelimChar, AQuoteChar: Char);
begin
  FFileName := AFileName;
  FStreamReader := TStreamReaderEx.Create(FFileName, AEncoding, True, BUFFER_SIZE);
  TStreamReaderEx(FStreamReader).FQuoteChar := AQuoteChar;
  TStreamReaderEx(FStreamReader).FDelimChar := ADelimChar;

  FDelimChar := ADelimChar;
  FQuoteChar := AQuoteChar;

  FColumns := TList<string>.Create;
end;

destructor TCSVReader.Destroy;
begin
  FreeAndNil(FColumns);
  FreeAndNil(FStreamReader);
  inherited;
end;

function TCSVReader.GetEOF: Boolean;
begin
  Result := FStreamReader.EndOfStream;
end;

function TCSVReader.GetFileSize: Int64;
begin
  Result := FStreamReader.BaseStream.Size;
end;

function TCSVReader.GetPosition: Int64;
begin
  Result := FStreamReader.BaseStream.Position;
end;

procedure TCSVReader.ReadRow;
begin
  //LLine := FStreamReader.ReadLine;
  //FColumns.DelimitedText := LLine;
  //FColumns.Clear;
  TStreamReaderEx(FStreamReader).ReadRow(FColumns);
end;

function TCSVReader.ColumnDef(const AIndex: Integer; const ADefault: string): string;
begin
  if (AIndex >= 0) and (AIndex < FColumns.Count) then
    Result := FColumns[AIndex]
  else
    Result := ADefault
end;

end.

