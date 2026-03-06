{ *********************************************************************** }
{ Copyright (c) 2010-2013 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.Hash;

{$SCOPEDENUMS ON}

interface

uses System.SysUtils, System.Classes, Rf.SysUtils, Rf.Types;

type

  TBytes = System.SysUtils.TBytes;

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
    class procedure ToBigEndian4(const InBuffer: array of UInt32; var OutBuffer: TBytes); static;
    class procedure ToBigEndian8(const InBuffer: array of UInt64; var OutBuffer: TBytes); static;
  public
    procedure AfterConstruction; override;

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
    /// Calculate Hash Value Of Bytes
    /// </summary>
    procedure CalcOfBytes(const ABytes: TBytes);
    procedure CalcOfStream(const Stream: TStream; BufferSize: Cardinal = 16384); virtual;
    procedure CalcOfFile(const AFileName: TFileName);
    /// <summary>
    /// Calculate Hash Value Of string (UTF8 encoding)
    /// </summary>
    procedure CalcOfString(const S: string); overload;
    /// <summary>
    /// Calculate Hash Value Of RawByteString
    /// </summary>
    procedure CalcOfString(const S: RawByteString); overload;

    { Calculate Hash Of ... }
    class function OfBuffer(const AData: Pointer; const ASize: Cardinal): TBytes;
    class function OfBytes(const ABytes: TBytes): TBytes;
    class function OfStream(const Stream: TStream): TBytes;
    class function OfFile(const AFileName: TFileName): TBytes;
    class function OfString(const S: string): TBytes; overload;
    class function OfString(const S: RawByteString): TBytes; overload;
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

    procedure CalcOfStream(const Stream: TStream; BufferSize: Cardinal = 16384); override;
  end;

implementation

{$POINTERMATH ON}

{ THash }

procedure THash.AfterConstruction;
begin
  inherited;
  SetLength(FValue, HashSize);
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

class procedure THash.ToBigEndian4(const InBuffer: array of UInt32; var OutBuffer: TBytes);
var
  Dst: PUInt32;
  i: Integer;
begin
  Dst := PUInt32(@OutBuffer[0]);
  for i := 0 to High(OutBuffer) shr 2 do
  begin
    Dst^ := SwapEndian(InBuffer[i]);
    Inc(Dst);
  end;
end;

class procedure THash.ToBigEndian8(const InBuffer: array of UInt64; var OutBuffer: TBytes);
var
  Dst: PUInt64;
  i: Integer;
begin
  Dst := PUInt64(@OutBuffer[0]);
  for i := 0 to High(OutBuffer) shr 3 do
  begin
    Dst^ := SwapEndian(InBuffer[i]);
    Inc(Dst);
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

procedure THash.CalcOfBytes(const ABytes: TBytes);
begin
  Initialize;
  Update(ABytes);
  Finalize;
end;

procedure THash.CalcOfString(const S: string);
begin
  CalcOfBytes(TEncoding.UTF8.GetBytes(S));
end;

procedure THash.CalcOfString(const S: RawByteString);
begin
//  CalcOfBuffer(PRawByteString(S), Length(S)); // PRawByteString(S) - its pointer to refc  counter
  CalcOfBuffer(PAnsiChar(S), Length(S));
end;

procedure THash.CalcOfStream(const Stream: TStream; BufferSize: Cardinal);
var
  Buffer: TBytes;
  CountRead: Cardinal;
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

class function THash.OfBytes(const ABytes: TBytes): TBytes;
begin
  with Create do
  try
    CalcOfBytes(ABytes);
    Result := Value;
  finally
    Free;
  end;
end;

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

class function THash.OfString(const S: RawByteString): TBytes;
begin
  with Create do
  try
    CalcOfString(S);
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

procedure TBlockHash.CalcOfStream(const Stream: TStream; BufferSize: Cardinal);
begin
  inherited CalcOfStream(Stream, BufferSize div BlockSize * BlockSize); // need align buffer for Block size
end;

procedure TBlockHash.Initialize;
begin
  FUsedBuffer := 0;
//  FillChar(FBlockBuffer, FBlockSize, 0);
//  FBlockSize := BlockSize;
end;

procedure TBlockHash.Update(const AData: Pointer; const ASize: Cardinal);
var
  PBuffer: PByte;
  Remind: Cardinal;
  BufFree: Cardinal;
begin
  PBuffer := AData;

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
    Inc(PBuffer, BufFree);
    Remind := ASize - BufFree;
    while Remind >= FBlockSize do
    begin
      UpdateBlock(PBuffer);
      Inc(PBuffer, FBlockSize);
      Dec(Remind, FBlockSize);
    end;
    FUsedBuffer := Remind;
    if FUsedBuffer > 0 then
      Move(PBuffer^, FBlockBuffer[0], FUsedBuffer);
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
