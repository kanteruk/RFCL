{ *********************************************************************** }
{ Copyright (c) 2007-2024 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.Storage;

{$I Rf.Defines.inc}

interface

uses
  System.TypInfo, System.SysUtils, System.Classes, System.Generics.Collections, System.Rtti,
  Rf.Types, Rf.SysUtils, Rf.Classes;

type

{ TRfStorage }

  ERfStorageError = class(Exception);

  TRfStorageClass = class of TRfStorage;

  TRfStorage = class abstract(TObject)
  private
    FSectionName: string;
    FParent: TRfStorage;
    FSections: TObjectDictionary<string, TRfStorage>;
  strict private
    class var FFormatConverter: TRfFormatConverter;
    class constructor Create;
    class destructor Destroy;
  protected
    function GetSection(const ASection: string): TRfStorage; virtual;
    class function GetSectionClass: TRfStorageClass; virtual; abstract;

    class procedure InitConverter; virtual;
    class function GetConverter: TRfFormatConverter; virtual;

    constructor Create(AParent: TRfStorage = nil; const ASectionName: string = ''); virtual;
  public
    class procedure Error(const Message: string); virtual;
  public
    destructor Destroy; override;

    property SectionName: string read FSectionName;
    property Parent: TRfStorage read FParent;
    property Sections[const ASection: string]: TRfStorage read GetSection; default;

    { Core Methods }

    procedure Update; dynamic;

    procedure ReadSections(ASections: TStrings); virtual; abstract;
    procedure ReadKeys(AKeys: TStrings); virtual; abstract;
    function DeleteSection(const ASection: string): Boolean; virtual; abstract;
    function DeleteKey(const AKey: string): Boolean; overload; virtual; abstract;
    function SectionExists(const ASection: string): Boolean; virtual;
    function ValueExists(const AKey: string): Boolean; overload; virtual;

    procedure ReadSection(const ASection: string; AKeys: TStrings); inline;

    function ReadIdent(const Ident: string; const Default: string = ''): string; overload; dynamic; abstract;
    procedure WriteIdent(const Ident: string; const Value: string); overload; dynamic; abstract;

    function ReadBuffer(const Ident: string; var Buffer; const Size: Integer): Integer; virtual;
    procedure WriteBuffer(const Ident: string; const Buffer; const Size: Integer); virtual;
    function ReadStream(const Ident: string; Stream: TStream): Int64; overload;virtual;
    procedure WriteStream(const Ident: string; Stream: TStream); overload;virtual;
    function ReadString(const Ident: string; const Default: string = ''): string; overload;virtual;
    procedure WriteString(const Ident: string; const Value: string); overload;virtual;
    function ReadChar(const Ident: string; const Default: Char = chNull): Char; overload;virtual;
    procedure WriteChar(const Ident: string; const Value: Char); overload;virtual;
    function ReadInteger(const Ident: string; const Default: Integer = 0): Integer; overload;virtual;
    procedure WriteInteger(const Ident: string; const Value: Integer); overload;virtual;
    function ReadBoolean(const Ident: string; const Default: Boolean = False): Boolean; overload;virtual;
    procedure WriteBoolean(const Ident: string; const Value: Boolean); overload;virtual;
    function ReadDWord(const Ident: string; const Default: DWord = 0): DWord; overload;virtual;
    procedure WriteDWord(const Ident: string; const Value: DWord); overload;virtual;
    function ReadFloat(const Ident: string; const Default: Double = 0): Double; overload;virtual;
    procedure WriteFloat(const Ident: string; const Value: Double); overload;virtual;
    function ReadDateTime(const Ident: string; const Default: TDateTime): TDateTime; overload;virtual;
    procedure WriteDateTime(const Ident: string; const Value: TDateTime); overload;virtual;
    function ReadDate(const Ident: string; const Default: TDateTime): TDateTime; overload;virtual;
    procedure WriteDate(const Ident: string; const Value: TDateTime); overload;virtual;
    function ReadTime(const Ident: string; const Default: TDateTime): TDateTime; overload;virtual;
    procedure WriteTime(const Ident: string; const Value: TDateTime); overload;virtual;
    function ReadPoint(const Ident: string; const Default: TPoint): TPoint; overload;virtual;
    procedure WritePoint(const Ident: string; const Value: TPoint); overload;virtual;
    function ReadRect(const Ident: string; const Default: TRect): TRect; overload;virtual;
    procedure WriteRect(const Ident: string; const Value: TRect); overload;virtual;
    procedure ReadStrings(const Ident: string; Strings: TStrings); overload;virtual;
    procedure WriteStrings(const Ident: string; Strings: TStrings); overload;virtual;

    procedure WriteSet(const Ident: string; ATypeInfo: PTypeInfo; const Value); overload;
    procedure ReadSet(const Ident: string; ATypeInfo: PTypeInfo; var Value); overload;

    procedure Write<T>(const Ident: string; const Value: T);
    function Read<T>(const Ident: string; const Default: T): T; overload;
    function Read<T>(const Ident: string): T; overload; inline;

    { Property }
    procedure WriteProperty(Instance: TObject; const PropName: string); overload;
    procedure ReadProperty(Instance: TObject; const PropName: string); overload;
    procedure WriteProperties(Instance: TObject; const PropNames: array of string); overload;
    procedure ReadProperties(Instance: TObject; const PropNames: array of string); overload;

    { Component }
    procedure WriteComponentAsStream(const Ident: string; Instance: TComponent); overload;
    function ReadComponentAsStream(const Ident: string; Instance: TComponent): TComponent; overload;
    procedure WriteComponentAsText(const Ident: string; Instance: TComponent); overload;
    function ReadComponentAsText(const Ident: string; Instance: TComponent): TComponent; overload;
    procedure WriteComponent(const AKey: string; Instance: TComponent; const AsText: Boolean = True); overload;
    function ReadComponent(const AKey: string; Instance: TComponent; const AsText: Boolean = True): TComponent; overload;
    procedure WriteComponent(Instance: TComponent; const AsText: Boolean = True); overload; inline;
    function ReadComponent(Instance: TComponent; const AsText: Boolean = True): TComponent; overload; inline;
  end;

{ IRfStoragePersist }

  IRfStoragePersist = interface
  ['{3F865D5D-AB74-4281-9AEF-C90A547396FB}']
    procedure LoadFromStorage(Storage: TRfStorage);
    procedure SaveToStorage(Storage: TRfStorage);
  end;

{ TRfCustomStorageProvider }

  TRfCustomStorageProvider = class(TRfComponent)
  protected
    FReadOnly: Boolean;
    FStorage: TRfStorage;
    procedure Change; dynamic;
    function GetStorageClass: TRfStorageClass; virtual; abstract;
  public
    function CreateStorage: TRfStorage; dynamic; abstract;
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;
    function Open: Boolean; dynamic;
    procedure Close; dynamic;
    function Update: Boolean; dynamic;
    property StorageClass: TRfStorageClass read GetStorageClass;
    property Storage: TRfStorage read FStorage;
    property ReadOnly: Boolean read FReadOnly;
  end;

  TRfCustomStorageProviderClass = class of TRfCustomStorageProvider;

  TRfStorageFormatConverter = class(TRfFormatConverter)
  public
    function BoolToStr(const Value: Boolean): string; override;
    function TryStrToInt(const S: string; out Value: Integer): Boolean; override;
    function TryStrToDWord(const S: string; out Value: DWord): Boolean; override;
  end;

implementation

{ TRfStorage }

class constructor TRfStorage.Create;
begin
  FFormatConverter := nil;
end;

class destructor TRfStorage.Destroy;
begin
  FreeAndNilA(FFormatConverter);
end;

constructor TRfStorage.Create(AParent: TRfStorage; const ASectionName: string);
begin
  inherited Create;
  FParent := AParent;
  FSectionName := ASectionName;

  FSections := nil;
end;

destructor TRfStorage.Destroy;
begin
  if Assigned(FSections) then
    FSections.Free;
  inherited;
end;

function TRfStorage.GetSection(const ASection: string): TRfStorage;
begin
  if FSections = nil then
    FSections := TObjectDictionary<string, TRfStorage>.Create([doOwnsValues]);

  if not FSections.TryGetValue(ASection, Result) then
  begin
    Result := GetSectionClass.Create(Self, ASection);
    FSections.Add(ASection, Result);
  end;
end;

class procedure TRfStorage.Error(const Message: string);
begin
  raise ERfStorageError.Create(Message);
end;

procedure TRfStorage.Update;
begin
  { do nothing }
end;

function TRfStorage.SectionExists(const ASection: string): Boolean;
var
  S: TStrings;
begin
  S := TStringList.Create;
  try
    Sections[ASection].ReadKeys(S);
    Result := S.Count > 0;
  finally
    S.Free;
  end;
end;

function TRfStorage.ValueExists(const AKey: string): Boolean;
var
  S: TStrings;
begin
  S := TStringList.Create;
  try
    ReadKeys(S);
    Result := S.IndexOf(AKey) >= 0;
  finally
    S.Free;
  end;
end;

procedure TRfStorage.WriteStream(const Ident: string; Stream: TStream);
var
  ASize: Integer;
  Buffer: Pointer;
begin
  ASize := Stream.Size - Stream.Position;
  if Stream is TMemoryStream then
    WriteBuffer(Ident, MakePointer(TMemoryStream(Stream).Memory, Stream.Position)^, ASize)
  else begin
    GetMem(Buffer, ASize);
    try
      Stream.ReadBuffer(Buffer^, ASize);
      WriteBuffer(Ident, Buffer^, ASize);
    finally
      FreeMem(Buffer);
    end;
  end;
end;

function TRfStorage.ReadStream(const Ident: string; Stream: TStream): Int64;
var
  Buffer: Pointer;
  P: Integer;
begin
  Result := ReadBuffer(Ident, Buffer, 0);
  if Result > 0 then
  begin
    if Stream is TMemoryStream then
    begin
      P := Stream.Position;
      Stream.Size := Stream.Size + Result;
      Result := ReadBuffer(Ident, MakePointer(TMemoryStream(Stream).Memory, P)^, Result);
    end
    else begin
      GetMem(Buffer, Result);
      try
        Result := ReadBuffer(Ident, Buffer^, Result);
        Stream.WriteBuffer(Buffer^, Result);
      finally
        FreeMem(Buffer);
      end;
    end;
  end;
end;

procedure TRfStorage.WriteSet(const Ident: string; ATypeInfo: PTypeInfo; const Value);
begin
  WriteIdent(Ident, TRfTypeInfo.SetToString(ATypeInfo, Value, True));
end;

procedure TRfStorage.ReadSet(const Ident: string; ATypeInfo: PTypeInfo; var Value);
var
  S: string;
begin
  S := ReadIdent(Ident, '');
  if S <> '' then
    TRfTypeInfo.TryStringToSet(ATypeInfo, S, Value);
end;

procedure TRfStorage.WriteComponentAsStream(const Ident: string; Instance: TComponent);
var
  Stream: TStream;
begin
  Stream := TMemoryStream.Create;
  try
    Stream.WriteComponent(Instance);
    Stream.First;
    WriteStream(Ident, Stream);
  finally
    Stream.Free;
  end;
end;

function TRfStorage.ReadComponentAsStream(const Ident: string; Instance: TComponent): TComponent;
var
  Stream: TStream;
begin
  Result := nil;
  Stream := TMemoryStream.Create;
  try
    if ReadStream(Ident, Stream) > 0 then
    begin
      Stream.First;
      Result := Stream.ReadComponent(Instance);
    end
  finally
    Stream.Free;
  end;
end;

procedure TRfStorage.WriteComponentAsText(const Ident: string; Instance: TComponent);
var
  Stream: TStream;
  ss: TStringStream;
  sl: TStrings;
begin
  Stream := TMemoryStream.Create;
  try
    Stream.WriteComponent(Instance);
    Stream.First;
    sl := TStringList.Create;
    try
      ss := TStringStream.Create('');
      try
        ObjectBinaryToText(Stream, ss);
        ss.First;
        sl.LoadFromStream(ss);
        WriteStrings(Ident, sl);
      finally
        ss.Free;
      end;
    finally
      sl.Free;
    end;
  finally
    Stream.Free;
  end;
end;

function TRfStorage.ReadComponentAsText(const Ident: string; Instance: TComponent): TComponent;
var
  Stream: TStream;
  ss: TStringStream;
  sl: TStrings;
begin
  Stream := TMemoryStream.Create;
  sl := TStringList.Create;
  try
    ReadStrings(Ident, sl);
    ss := TStringStream.Create(sl.Text);
    try
      ss.First;
      ObjectTextToBinary(ss, Stream);
      Stream.First;
      Result := Stream.ReadComponent(Instance);
    finally
      ss.Free;
    end;
  finally
    sl.Free;
    Stream.Free;
  end;
end;

procedure TRfStorage.WriteComponent(const AKey: string; Instance: TComponent; const AsText: Boolean = True);
begin
  if AsText then
    WriteComponentAsText(AKey, Instance)
  else
    WriteComponentAsStream(AKey, Instance)
end;

function TRfStorage.ReadComponent(const AKey: string; Instance: TComponent; const AsText: Boolean = True): TComponent;

  procedure ReadPropertiesAsText(const Text: string);
  var
    Mem: TMemoryStream;
     ss: TStringStream;
  begin
    Mem := nil;
    ss := nil;
    try
    try
      Mem := TMemoryStream.Create;
      ss := TStringStream.Create(Text);
      ObjectTextToBinary(ss, Mem);
      Mem.Position := 0;
  //    ReadPropValues(Mem);
  //    Result := Mem.ReadComponent(Owner);
      Result := Mem.ReadComponent(Instance);
    finally
      ss.Free;
      Mem.Free;
    end;
    except
      assert(false);
    end;
  end;

var
  ss: TStringStream;
  Strings: TStrings;
begin
  Result := nil;
  if not ValueExists(AKey) then Exit;
  Strings := TStringList.Create;
  try
    ReadStrings(AKey, Strings);
    if Strings.Count = 0 then
      ReadComponentAsStream(AKey, Instance)
    else begin
      ss := TStringStream.Create(Strings[0]);
      try
        case TestStreamFormat(ss) of
          sofBinary:
            ReadComponentAsStream(AKey, Instance);
          sofText, sofUTF8Text:
            ReadPropertiesAsText(Strings.Text);
        end;
      finally
        ss.Free;
      end;
    end;
  finally
    Strings.Free;
  end;
end;

function TRfStorage.ReadBuffer(const Ident: string; var Buffer; const Size: Integer): Integer;
var
  S: string;
begin
  S := ReadIdent(Ident);
  if Size = 0 then
  begin
    Result := Length(S) div 2;
    Exit;
  end;
  {$IFNDEF NEXTGEN}
  Result := HexToBin(PChar(S), PChar(@Buffer), Size);
  {$ELSE}
  Result := 0; // ToDo
  {$ENDIF}
end;

procedure TRfStorage.WriteBuffer(const Ident: string; const Buffer; const Size: Integer);
begin
  if Size > 0 then
    WriteIdent(Ident, BinToHexStr(Buffer, Size));
end;

function TRfStorage.ReadString(const Ident, Default: string): string;
begin
  Result := ReadIdent(Ident, Default);
end;

procedure TRfStorage.WriteString(const Ident, Value: string);
begin
  WriteIdent(Ident, Value);
end;

function TRfStorage.ReadInteger(const Ident: string; const Default: Integer): Integer;
begin
  Result := GetConverter.StrToIntDef(ReadIdent(Ident), Default);
end;

procedure TRfStorage.WriteInteger(const Ident: string; const Value: Integer);
begin
  WriteIdent(Ident, GetConverter.IntToStr(Value));
end;

function TRfStorage.ReadBoolean(const Ident: string; const Default: Boolean): Boolean;
begin
  Result := GetConverter.StrToBoolDef(ReadIdent(Ident), Default);
end;

procedure TRfStorage.WriteBoolean(const Ident: string; const Value: Boolean);
begin
  WriteIdent(Ident, GetConverter.BoolToStr(Value));
end;

function TRfStorage.ReadDWord(const Ident: string; const Default: DWord): DWord;
begin
  Result := GetConverter.StrToDWordDef(ReadIdent(Ident), Default);
end;

procedure TRfStorage.WriteDWord(const Ident: string; const Value: DWord);
begin
  WriteIdent(Ident, GetConverter.DWordToStr(Value));
end;

function TRfStorage.ReadFloat(const Ident: string; const Default: Double): Double;
begin
  if not GetConverter.TryStrToFloat(ReadIdent(Ident), Result) then
    Result := Default
end;

procedure TRfStorage.WriteFloat(const Ident: string; const Value: Double);
begin
  WriteIdent(Ident, GetConverter.FloatToStr(Value));
end;

function TRfStorage.ReadDateTime(const Ident: string; const Default: TDateTime): TDateTime;
begin
  Result := GetConverter.StrToDateTimeDef(ReadIdent(Ident), Default);
end;

procedure TRfStorage.WriteDateTime(const Ident: string; const Value: TDateTime);
begin
  WriteIdent(Ident, GetConverter.DateTimeToStr(Value));
end;

function TRfStorage.ReadDate(const Ident: string; const Default: TDateTime): TDateTime;
begin
//  Result := ReadDateTime(Ident, Default);
  Result := GetConverter.StrToDateDef(ReadIdent(Ident), Default);
end;

procedure TRfStorage.WriteDate(const Ident: string; const Value: TDateTime);
begin
  WriteIdent(Ident, GetConverter.DateToStr(Value));
end;

function TRfStorage.ReadTime(const Ident: string; const Default: TDateTime): TDateTime;
begin
//  Result := ReadDateTime(Ident, Default);
  Result := GetConverter.StrToTimeDef(ReadIdent(Ident), Default);
end;

procedure TRfStorage.WriteTime(const Ident: string; const Value: TDateTime);
begin
  WriteIdent(Ident, GetConverter.TimeToStr(Value));
end;

function TRfStorage.ReadChar(const Ident: string; const Default: Char): Char;
begin
  Result := GetConverter.IdentToCharDef(ReadIdent(Ident), Default);
end;

procedure TRfStorage.WriteChar(const Ident: string; const Value: Char);
begin
  WriteIdent(Ident, GetConverter.CharToIdent(Value));
end;

function TRfStorage.ReadPoint(const Ident: string; const Default: TPoint): TPoint;
begin
  Result := GetConverter.StrToPointDef(ReadIdent(Ident), Default);
end;

procedure TRfStorage.WritePoint(const Ident: string; const Value: TPoint);
begin
  WriteIdent(Ident, GetConverter.PointToStr(Value));
end;

function TRfStorage.ReadRect(const Ident: string; const Default: TRect): TRect;
begin
  Result := GetConverter.StrToRectDef(ReadIdent(Ident), Default);
end;

procedure TRfStorage.WriteRect(const Ident: string; const Value: TRect);
begin
  WriteIdent(Ident, GetConverter.RectToStr(Value));
end;

procedure TRfStorage.ReadStrings(const Ident: string; Strings: TStrings);
begin
  Strings.Text := ReadString(Ident, Strings.Text);
end;

procedure TRfStorage.WriteStrings(const Ident: string; Strings: TStrings);
begin
  WriteString(Ident, Strings.Text);
end;

procedure TRfStorage.WriteProperty(Instance: TObject; const PropName: string);
{var
  PropInfo: PPropInfo;}
begin
{  if Instance = nil then Exit;
  PropInfo := GetPropInfo(Instance, PropName);
  if PropInfo = nil then Exit; }

  WriteIdent(PropName, TRfTypeInfo.PropertyToStringEx(Instance, PropName));
end;

procedure TRfStorage.ReadProperty(Instance: TObject; const PropName: string);
var
  S: string;
begin
  S := ReadIdent(PropName, '');
  if S <> '' then
    TRfTypeInfo.StringToPropertyEx(Instance, PropName, S);
end;

procedure TRfStorage.WriteProperties(Instance: TObject; const PropNames: array of string);
var
  i: Integer;
begin
  for i := 0 to High(PropNames) do
    WriteProperty(Instance, PropNames[i]);
end;

procedure TRfStorage.ReadProperties(Instance: TObject; const PropNames: array of string);
var
  i: Integer;
begin
  for i := 0 to High(PropNames) do
    ReadProperty(Instance, PropNames[i]);
end;

procedure TRfStorage.ReadSection(const ASection: string; AKeys: TStrings);
begin
  Sections[ASection].ReadKeys(AKeys);
end;

function TRfStorage.ReadComponent(Instance: TComponent; const AsText: Boolean): TComponent;
begin
  Result := ReadComponent(Instance.Name, Instance, AsText);
end;

procedure TRfStorage.WriteComponent(Instance: TComponent; const AsText: Boolean);
begin
  WriteComponent(Instance.Name, Instance, AsText);
end;

procedure TRfStorage.Write<T>(const Ident: string; const Value: T);
begin
  case {$IFNDEF Delphi20Up}PTypeInfo(TypeInfo(T)).Kind{$ELSE}GetTypeKind(T){$ENDIF} of
    TTypeKind.tkString, TTypeKind.tkWString, TTypeKind.tkUString:
      WriteString(Ident, { TValue.From<T>(Value).AsString} PString(@Value)^);
    TTypeKind.tkChar: // AnsiChar
      {$IFNDEF NEXTGEN}
      WriteChar(Ident, Char(PAnsiChar(@Value)^));
      {$ELSE}
      WriteChar(Ident, Char(PChar(@Value)^));
      {$ENDIF}
    TTypeKind.tkWChar:
      WriteChar(Ident, Char(PWideChar(@Value)^));
    TTypeKind.tkInteger:// todo cardinal
      WriteInteger(Ident, TValue.From<T>(Value).AsInteger);
    TTypeKind.tkInt64:
      WriteInteger(Ident, TValue.From<T>(Value).AsInt64);
    TTypeKind.tkFloat:
          if TypeInfo(T) = System.TypeInfo(TDate) then
            WriteDate(Ident, TValue.From<T>(Value).AsExtended)
          else if TypeInfo(T) = System.TypeInfo(TTime) then
            WriteTime(Ident, TValue.From<T>(Value).AsExtended)
          else if TypeInfo(T) = System.TypeInfo(TDateTime) then
            WriteDateTime(Ident, TValue.From<T>(Value).AsExtended)
          else
            WriteFloat(Ident, TValue.From<T>(Value).AsExtended);
    TTypeKind.tkEnumeration:
      if TypeInfo(T) = TypeInfo(Boolean) then
        WriteBoolean(Ident, TValue.From<T>(Value).AsBoolean)
      else
        WriteInteger(Ident, TValue.From<T>(Value).AsInteger);
    TTypeKind.tkSet:
      WriteSet(Ident, TypeInfo(T), Value)
    else
      if TypeInfo(T) = TypeInfo(TPoint) then
        WritePoint(Ident, TValue.From<T>(Value).AsType<TPoint>)
      else if TypeInfo(T) = TypeInfo(TRect) then
        WriteRect(Ident, TValue.From<T>(Value).AsType<TRect>)
      else
        Assert(False, GetTypeName(TypeInfo(T)) + ' ' + Ord(PTypeInfo(TypeInfo(T)).Kind).ToString);
  end;
end;

function TRfStorage.Read<T>(const Ident: string; const Default: T): T;
begin
  case {$IFNDEF Delphi20Up}PTypeInfo(TypeInfo(T)).Kind{$ELSE}GetTypeKind(T){$ENDIF} of
    TTypeKind.tkString, TTypeKind.tkWString, TTypeKind.tkUString:
      Result := TValue.From<string>(ReadString(Ident, TValue.From<T>(Default).AsString)).AsType<T>;
    TTypeKind.tkChar: // AnsiChar
      {$IFNDEF NEXTGEN}
      Result := TValue.From<AnsiChar>(AnsiChar(ReadChar(Ident, Char(TValue.From<T>(Default).AsType<AnsiChar>)))).AsType<T>;
      {$ELSE}
      Result := TValue.From<Char>(Char(ReadChar(Ident, Char(TValue.From<T>(Default).AsType<Char>)))).AsType<T>;
      {$ENDIF}
    TTypeKind.tkWChar:
      Result := TValue.From<Char>(ReadChar(Ident, TValue.From<T>(Default).AsType<Char>)).AsType<T>;
    TTypeKind.tkInteger:
      Result := TValue.From<Integer>(ReadInteger(Ident, TValue.From<T>(Default).AsInteger)).AsType<T>;
    TTypeKind.tkInt64:
      Result := TValue.From<Int64>(ReadInteger(Ident, TValue.From<T>(Default).AsInt64)).AsType<T>;
    TTypeKind.tkFloat:
      if TypeInfo(T) = System.TypeInfo(TDate) then
        Result := TValue.From<TDate>(ReadDate(Ident, TValue.From<T>(Default).AsExtended)).AsType<T>
      else if TypeInfo(T) = System.TypeInfo(TTime) then
        Result := TValue.From<TTime>(ReadTime(Ident, TValue.From<T>(Default).AsExtended)).AsType<T>
      else if TypeInfo(T) = System.TypeInfo(TDateTime) then
        Result := TValue.From<TDateTime>(ReadDateTime(Ident, TValue.From<T>(Default).AsExtended)).AsType<T>
      else
        Result := TValue.From<Extended>(ReadFloat(Ident, TValue.From<T>(Default).AsExtended)).AsType<T>;
    TTypeKind.tkEnumeration:
      if TypeInfo(T) = TypeInfo(Boolean) then
        Result := TValue.From<Boolean>(ReadBoolean(Ident, TValue.From<T>(Default).AsBoolean)).AsType<T>
      else
        Result := TValue.From<Integer>(ReadInteger(Ident, TValue.From<T>(Default).AsInteger)).AsType<T>;
    TTypeKind.tkSet:
      ReadSet(Ident, TypeInfo(T), Result)
    else begin
      if TypeInfo(T) = TypeInfo(TPoint) then
        Result := TValue.From<TPoint>(ReadPoint(Ident, TValue.From<T>(Default).AsType<TPoint>)).AsType<T>
      else if TypeInfo(T) = TypeInfo(TRect) then
        Result := TValue.From<TRect>(ReadRect(Ident, TValue.From<T>(Default).AsType<TRect>)).AsType<T>
      else begin
        Assert(False, GetTypeName(TypeInfo(T)) + ' ' + Ord(PTypeInfo(TypeInfo(T)).Kind).ToString);
        Result := Default;
      end
    end
  end;
end;

function TRfStorage.Read<T>(const Ident: string): T;
begin
  Result := Read<T>(Ident, Default(T));
end;

{ TRfCustomStorageProvider }

constructor TRfCustomStorageProvider.Create(AOwner: TComponent);
begin
  inherited;
  FStorage := nil;
end;

destructor TRfCustomStorageProvider.Destroy;
begin
  Close;
  inherited;
end;

procedure TRfCustomStorageProvider.Change;
begin
  { Do Nothing }
end;

function TRfCustomStorageProvider.Open: Boolean;
begin
  if Assigned(FStorage) then
    Result := True
  else begin
    FStorage := CreateStorage;
    Result := FStorage <> nil;
  end;
end;

procedure TRfCustomStorageProvider.Close;
begin
  FreeAndNilA(FStorage);
end;

function TRfCustomStorageProvider.Update: Boolean;
begin
  Result := Assigned(FStorage) and not FReadOnly;
  if Result then
    FStorage.Update;
end;

class procedure TRfStorage.InitConverter;
begin
  if FFormatConverter <> nil then Exit;

  FFormatConverter := TRfStorageFormatConverter.Create;
  FFormatConverter.FormatSettings := TFormatSettings.Invariant;
  with FFormatConverter.FormatSettings do
  begin
    DecimalSeparator := '.';
    ShortDateFormat := 'yyyy-MM-dd';
  end;
end;

class function TRfStorage.GetConverter: TRfFormatConverter;
begin
  InitConverter;
  Result := FFormatConverter;
end;

{ TRfStorageFormatConverter }

function TRfStorageFormatConverter.BoolToStr(const Value: Boolean): string;
begin
  if Value then
    Result := DefaultTrueBoolStr
  else
    Result := DefaultFalseBoolStr;
end;

function TRfStorageFormatConverter.TryStrToInt(const S: string; out Value: Integer): Boolean;
begin
  if (Length(S) > 2) and (S[1] = '0') and ((S[2] = 'X') or (S[2] = 'x')) then
    Result := inherited TryStrToInt('$' + Copy(S, 3, MaxInt), Value)
  else
    Result := inherited TryStrToInt(S, Value)
end;

function TRfStorageFormatConverter.TryStrToDWord(const S: string; out Value: DWord): Boolean;
begin
  if (Length(S) > 2) and (S[1] = '0') and ((S[2] = 'X') or (S[2] = 'x')) then
    Result := inherited TryStrToDWord('$' + Copy(S, 3, MaxInt), Value)
  else
    Result := inherited TryStrToDWord(S, Value)
end;

end.


