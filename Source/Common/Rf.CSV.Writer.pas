{ *********************************************************************** }
{ Copyright (c) 2010-2020 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.CSV.Writer;

interface

uses
  System.SysUtils, System.Classes;

type
  /// <summary>
  ///  class for write csv file
  /// </summary>
  TCSVWriter = class(TObject)
  private const
    BUFFER_SIZE = 64 * 1024;
  private
    FFileName: TFileName;
    FStreamWriter: TStreamWriter;
    FIsBeginOfRow: Boolean;
    FDelimChar: Char;
    FQuoteChar: Char;
    procedure WriteColumnDelimiter; inline;
  public
    constructor Create(const AFileName: TFileName; const AEncoding: TEncoding; const ADelimChar, AQuoteChar: Char); virtual;
    destructor Destroy; override;

    property FileName: TFileName read FFileName;
    property DelimChar: Char read FDelimChar;
    property QuoteChar: Char read FQuoteChar;

    procedure NewRow;
    procedure WriteValue(const AValue: string);
    procedure WriteValueNull;
  end;

implementation

{ TCSVWriter }

constructor TCSVWriter.Create(const AFileName: TFileName; const AEncoding: TEncoding; const ADelimChar, AQuoteChar: Char);
begin
  FFileName := AFileName;
  FStreamWriter := TStreamWriter.Create(FFileName, False, AEncoding, BUFFER_SIZE);
  FStreamWriter.AutoFlush := False;

  FDelimChar := ADelimChar;
  FQuoteChar := AQuoteChar;

  FIsBeginOfRow := True;
end;

destructor TCSVWriter.Destroy;
begin
  FreeAndNil(FStreamWriter);
  inherited;
end;

procedure TCSVWriter.NewRow;
begin
  FStreamWriter.WriteLine;
  FIsBeginOfRow := True;
end;

procedure TCSVWriter.WriteColumnDelimiter;
begin
  if FIsBeginOfRow then
    FIsBeginOfRow := False
  else
    FStreamWriter.Write(FDelimChar);
end;

procedure TCSVWriter.WriteValue(const AValue: string);
begin
  WriteColumnDelimiter;
  if FQuoteChar <> #0 then
    FStreamWriter.Write(AValue.QuotedString(FQuoteChar))
  else
    FStreamWriter.Write(AValue);
end;

procedure TCSVWriter.WriteValueNull;
begin
  WriteColumnDelimiter;
end;

end.

