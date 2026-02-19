{ *********************************************************************** }
{ Copyright (c) 2010-2013 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.Hash;

{$SCOPEDENUMS ON}

interface

uses System.SysUtils, System.Classes, Rf.SysUtils;

type

  THashType = (Checksum, Cryptographic);

  /// <summary>
  /// Abstract Hash Class
  /// </summary>
  THash = class abstract(TObject)
  protected
    FValue: TBytes;
    procedure Initialize; virtual; abstract;
    procedure Update(const AData: Pointer; const ASize: Cardinal); overload; virtual; abstract;
    procedure Update(const AData; const ASize: Cardinal); overload; inline;
    procedure Update(const AData: TBytes; const ALength: Cardinal = 0); overload; inline;
    procedure Finalize; virtual; abstract;

    procedure SetValueFromBuffer(const Buffer: Pointer; const Size: Integer; const Inverted: Boolean = False);
    class procedure ToBigEndian4(const InBuffer: array of Cardinal; var OutBuffer: TBytes); static;
    class procedure ToBigEndian8(const InBuffer: array of UInt64; var OutBuffer: TBytes); static;
  public
    procedure AfterConstruction; override;
    procedure BeforeDestruction; override;

    class function HashType: THashType; virtual; abstract;
    function HashSize: Cardinal; virtual; abstract;

    property Value: TBytes read FValue;
    function ValueAsString: string; inline;

    function Equals(Obj: TObject): Boolean; override;

    /// <summary>
    /// Calculate Hash Value Of Buffer
    /// </summary>
    procedure CalcOfBuffer(const AData: Pointer; const ASize: Cardinal);
    /// <summary>
    /// Calculate Hash Value Of string
    /// </summary>
    procedure CalcOfString(const S: string); overload;
    {$IFNDEF NEXTGEN}
    procedure CalcOfStringA(const S: AnsiString);
    procedure CalcOfStringW(const S: WideString);
    {$ENDIF}
    procedure CalcOfString(const S: RawByteString); overload;
    procedure CalcOfStream(const Stream: TStream); virtual;
    procedure CalcOfFile(const AFileName: TFileName);
    procedure CalcOfBytes(const ABytes: TBytes);

    { Calculate Hash Of ... }
    class function OfBuffer(const AData: Pointer; const ASize: Cardinal): TBytes;
    class function OfString(const S: string): TBytes;
    {$IFNDEF NEXTGEN}
    class function OfStringA(const S: AnsiString): TBytes;
    class function OfStringW(const S: WideString): TBytes;
    {$ENDIF}
    class function OfStream(const Stream: TStream): TBytes;
    class function OfFile(const AFileName: TFileName): TBytes;
  end;

  THashClass = class of THash;

  /// <summary>
  /// Abstract Block Hash Class
  /// </summary>
  TBlockHash = class abstract(THash)
  protected
    FBlockBuffer: TBytes;
    FBlockSize: Cardinal;
    FUsedBuffer: Cardinal;
    procedure Initialize; override;
    procedure Update(const AData: Pointer; const ASize: Cardinal); override;
    procedure UpdateBlock(const Block: Pointer); virtual; abstract;
    property UsedBuffer: Cardinal read FUsedBuffer;
    function GetPadBuffer: TBytes; virtual; abstract;
    procedure Finalize; override;
  public
    procedure AfterConstruction; override;
    procedure BeforeDestruction; override;

    function BlockSize: Cardinal; virtual; abstract; { Block size in Bytes }

    procedure CalcOfStream(const Stream: TStream); override;
  end;

implementation

{ THash }

procedure THash.AfterConstruction;
begin
  inherited;
  SetLength(FValue, HashSize);
end;

procedure THash.BeforeDestruction;
begin
  System.Finalize(FValue);
  inherited;
end;

procedure THash.Update(const AData; const ASize: Cardinal);
begin
  Update(PByte(@AData), ASize);
end;

procedure THash.Update(const AData: TBytes; const ALength: Cardinal);
var
  L: Cardinal;
begin
  if ALength = 0 then
    L := Length(AData)
  else
    L := ALength;
  if L = 0 then Exit;
  Update(@AData[0], L);
end;

procedure THash.SetValueFromBuffer(const Buffer: Pointer; const Size: Integer; const Inverted: Boolean);
var
  i: Integer;
begin
  if Inverted then
    for i := 0 to Size - 1 do
      FValue[i] := PByteArray(Buffer)[Size-1 - i]
  else
    Move(Buffer^, FValue[0], Size)
    {for i := 0 to Size - 1 do
      FValue[i] := PByteArray(Buffer)[i]}
end;

class procedure THash.ToBigEndian4(const InBuffer: array of Cardinal; var OutBuffer: TBytes);
var
  i, v: Integer;
begin
  for i := 0 to High(OutBuffer) shr 2 do
  begin
    v := i shl 2;
    OutBuffer[v + 0] := LongRec(InBuffer[i]).Bytes[3];
    OutBuffer[v + 1] := LongRec(InBuffer[i]).Bytes[2];
    OutBuffer[v + 2] := LongRec(InBuffer[i]).Bytes[1];
    OutBuffer[v + 3] := LongRec(InBuffer[i]).Bytes[0];
    //PCardinal(@OutBuffer[v + 0])^ := SwapEndian(InBuffer[i]);
  end;
end;

class procedure THash.ToBigEndian8(const InBuffer: array of UInt64; var OutBuffer: TBytes);
var
  i, v: Integer;
begin
  for i := 0 to High(OutBuffer) shr 3 do
  begin
    v := i shl 3;
    OutBuffer[v + 0] := Int64Rec(InBuffer[i]).Bytes[7];
    OutBuffer[v + 1] := Int64Rec(InBuffer[i]).Bytes[6];
    OutBuffer[v + 2] := Int64Rec(InBuffer[i]).Bytes[5];
    OutBuffer[v + 3] := Int64Rec(InBuffer[i]).Bytes[4];
    OutBuffer[v + 4] := Int64Rec(InBuffer[i]).Bytes[3];
    OutBuffer[v + 5] := Int64Rec(InBuffer[i]).Bytes[2];
    OutBuffer[v + 6] := Int64Rec(InBuffer[i]).Bytes[1];
    OutBuffer[v + 7] := Int64Rec(InBuffer[i]).Bytes[0];
  end;
end;

function THash.ValueAsString: string;
begin
  Result := BytesToHexString(Value);
end;

function THash.Equals(Obj: TObject): Boolean;
begin
  Result := (Obj = Self) or
    ((Obj is THash) and BytesEquals(THash(Obj).Value, FValue))
end;

procedure THash.CalcOfBuffer(const AData: Pointer; const ASize: Cardinal);
begin
  Initialize;
  Update(AData, ASize);
  Finalize;
end;

procedure THash.CalcOfString(const S: string);
begin
  CalcOfBuffer(PChar(S), Length(S) * SizeOf(Char));
end;

{$IFNDEF NEXTGEN}
procedure THash.CalcOfStringA(const S: AnsiString);
begin
  CalcOfBuffer(PAnsiChar(S), Length(S) * SizeOf(AnsiChar));
end;

procedure THash.CalcOfStringW(const S: WideString);
begin
  CalcOfBuffer(PWideChar(S), Length(S) * SizeOf(WideChar));
end;
{$ENDIF}

procedure THash.CalcOfString(const S: RawByteString);
begin
//  CalcOfBuffer(PRawByteString(S), Length(S)); // PRawByteString(S) - its pointer to refc  counter
  CalcOfBuffer(PAnsiChar(S), Length(S));
end;

procedure THash.CalcOfBytes(const ABytes: TBytes);
begin
  CalcOfBuffer(@ABytes[0], Length(ABytes));
end;

procedure THash.CalcOfStream(const Stream: TStream);
const
  BufferSize = 16384; // 16Kb
var
  Buffer: TBytes;
  CountRead: Integer;
begin
  Initialize;
  if Stream is TMemoryStream then
    with TMemoryStream(Stream) do
      Update(Memory, Size)
  else begin
    SetLength(Buffer, BufferSize);
    while True do
    begin
      CountRead := Stream.Read(Buffer[0], BufferSize);
      if CountRead = 0 then
        Break;
      Update(Buffer[0], CountRead);
    end;
  end;
  Finalize;
end;

procedure THash.CalcOfFile(const AFileName: TFileName);
var
  Stream: TStream;
begin
  Stream := TFileStream.Create(AFileName, fmOpenRead or fmShareDenyWrite);
  try
    CalcOfStream(Stream);
  finally
    Stream.Free;
  end;
end;

class function THash.OfBuffer(const AData: Pointer; const ASize: Cardinal): TBytes;
begin
  with Create do
  try
    CalcOfBuffer(AData, ASize);
    Result := Value;
  finally
    Free;
  end;
end;

class function THash.OfString(const S: string): TBytes;
begin
  with Create do
  try
    CalcOfString(S);
    Result := Value;
  finally
    Free;
  end;
end;

{$IFNDEF NEXTGEN}
class function THash.OfStringA(const S: AnsiString): TBytes;
begin
  with Create do
  try
    CalcOfStringA(S);
    Result := Value;
  finally
    Free;
  end;
end;

class function THash.OfStringW(const S: WideString): TBytes;
begin
  with Create do
  try
    CalcOfStringW(S);
    Result := Value;
  finally
    Free;
  end;
end;
{$ENDIF}

class function THash.OfStream(const Stream: TStream): TBytes;
begin
  with Create do
  try
    CalcOfStream(Stream);
    Result := Value;
  finally
    Free;
  end;
end;

class function THash.OfFile(const AFileName: TFileName): TBytes;
begin
  with Create do
  try
    CalcOfFile(AFileName);
    Result := Value;
  finally
    Free;
  end;
end;

{ TBlockHash }

procedure TBlockHash.AfterConstruction;
begin
  inherited;
  FBlockSize := BlockSize;
  SetLength(FBlockBuffer, FBlockSize);
end;

procedure TBlockHash.BeforeDestruction;
begin
  System.Finalize(FBlockBuffer);
  inherited;
end;

procedure TBlockHash.CalcOfStream(const Stream: TStream);
var
  BufferSize: Cardinal;
  Buffer: TBytes;
  CountRead: LongInt;
begin
  Initialize;

  BufferSize := 16384; // 16Kb
  BufferSize := BufferSize div BlockSize * BlockSize;

  if Stream is TMemoryStream then
    with TMemoryStream(Stream) do
      Update(Memory, Size)
  else begin
    SetLength(Buffer, BufferSize);
    try
      while True do
      begin
        CountRead := Stream.Read(Buffer[0], BufferSize);
        if CountRead = 0 then
          Break;
        Update(@Buffer[0], CountRead);
      end;
    finally
      SetLength(Buffer,0);
    end;
  end;
  Finalize;
end;

procedure TBlockHash.Initialize;
begin
  FUsedBuffer := 0;
//  FillChar(FBlockBuffer, FBlockSize, 0);
//  FBlockSize := BlockSize;
end;

{$POINTERMATH ON}
procedure TBlockHash.Update(const AData: Pointer; const ASize: Cardinal);
var
  i: Cardinal;
  BufFree: Cardinal;
  PBuffer: PByte;
{  LSize: LongWord;
  Count: Integer;
  LBufLen: Cardinal;
  LRest: Integer;  }
begin
  PBuffer := AData;
{
  LSize := ASize;
  LBufLen := BlockSize;
  // Code Option A
  Count := (LSize + FUsedBuffer) div LBufLen;
  if Count > 0  then
  begin
    LRest := LBufLen - FUsedBuffer;
    Move(PBuffer^, FBlockBuffer[FUsedBuffer], LRest);
    Inc(PBuffer, LRest);
    Dec(LSize, LRest);
    UpdateBlock(@FBlockBuffer[0]);
    for I := 1 to Count - 1 do
    begin
      Move(PBuffer^, FBlockBuffer[0], LBufLen);
      Inc(PBuffer, LBufLen);
      Dec(LSize, LBufLen);
      UpdateBlock(@FBlockBuffer[0]);
    end;
    FUsedBuffer := 0;
  end;
  Move(PBuffer^, FBlockBuffer[FUsedBuffer], LSize);
  Inc(FUsedBuffer, LSize);
exit; }

  BufFree := FBlockSize - FUsedBuffer;
  if ASize >= BufFree then
  begin
    if BufFree = FBlockSize then
      UpdateBlock(PBuffer)
    else if BufFree > 0 then
    begin
      Move(PBuffer^, FBlockBuffer[FUsedBuffer], BufFree);
      UpdateBlock(@FBlockBuffer[0]);
    end;
    i := BufFree;
    while i + FBlockSize <= ASize do
    begin
      UpdateBlock(Pointer(PBuffer + i));
      Inc(i, FBlockSize);
    end;
    FUsedBuffer := ASize - i;
    if FUsedBuffer > 0 then
      Move(Pointer(PBuffer + i)^, FBlockBuffer[0], FUsedBuffer);
  end
  else begin
    Move(PBuffer^, FBlockBuffer[FUsedBuffer], ASize);
    Inc(FUsedBuffer, ASize);
  end;
end;

procedure TBlockHash.Finalize;
begin
  Update(GetPadBuffer);
end;

end.
