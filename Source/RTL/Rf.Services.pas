{ *********************************************************************** }
{ Copyright (c) 2015-2017 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.Services;

interface

{$SCOPEDENUMS ON}

uses
  System.Types, System.SysUtils, System.Generics.Collections;

type

  TRfServices = class
  private
    FServicesList: TDictionary<TGUID, IInterface>;
    class var FCurrent: TRfServices;
    class var FCurrentReleased: Boolean;
    class procedure ReleaseCurrent;
    class function GetCurrent: TRfServices; static;
    class constructor CreateClass;
  public
    constructor Create; virtual;
    destructor Destroy; override;
    procedure AddService(const AServiceGUID: TGUID; const AService: IInterface);
    procedure RemoveService(const AServiceGUID: TGUID);
    function GetService(const AServiceGUID: TGUID): IInterface;
    function SupportsService(const AServiceGUID: TGUID): Boolean; overload;
    function SupportsService(const AServiceGUID: TGUID; out AService): Boolean; overload;
    class property Current: TRfServices read GetCurrent;

    class procedure Add(const AServiceGUID: TGUID; const AService: IInterface); static;
    class procedure Remove(const AServiceGUID: TGUID); static;
    class function Supports(const AServiceGUID: TGUID; out AService): Boolean; overload; static;
  end;

implementation

uses
  System.RTLConsts;

{ TRfServices }

class constructor TRfServices.CreateClass;
begin
  FCurrent := nil;
  FCurrentReleased := False;
end;

procedure TRfServices.AddService(const AServiceGUID: TGUID; const AService: IInterface);
var
  LService: IInterface;
begin
  if not FServicesList.ContainsKey(AServiceGUID) then
  begin
    if System.SysUtils.Supports(AService, AServiceGUID, LService) then
      FServicesList.Add(AServiceGUID, AService)
    else if AService = nil then
      raise EArgumentNilException.Create(SArgumentNil) at ReturnAddress
    else if AService is TObject then
      raise EArgumentException.CreateFmt('Class %0:s does not support interface %1:s',
        [TObject(AService).ClassName, GUIDToString(AServiceGUID)]) at ReturnAddress
    else
      raise EArgumentException.Create(sArgumentInvalid) at ReturnAddress;
  end
  else
    raise EListError.CreateFmt('Service %s already registered', [GUIDToString(AServiceGUID)]) at ReturnAddress;
end;

constructor TRfServices.Create;
begin
  inherited;
  FServicesList := TDictionary<TGUID, IInterface>.Create;
end;

destructor TRfServices.Destroy;
begin
  FreeAndNil(FServicesList);
  inherited;
end;

class procedure TRfServices.ReleaseCurrent;
begin
  FCurrentReleased := True;
  FreeAndNil(FCurrent);
end;

class function TRfServices.GetCurrent: TRfServices;
begin
  if (FCurrent = nil) and not FCurrentReleased then
    FCurrent := TRfServices.Create;
  Result := FCurrent;
end;

function TRfServices.GetService(const AServiceGUID: TGUID): IInterface;
begin
  System.SysUtils.Supports(FServicesList.Items[AServiceGUID], AServiceGUID, Result);
end;

procedure TRfServices.RemoveService(const AServiceGUID: TGUID);
begin
  FServicesList.Remove(AServiceGUID);
end;

function TRfServices.SupportsService(const AServiceGUID: TGUID; out AService): Boolean;
begin
  if FServicesList.ContainsKey(AServiceGUID) then
    Result := System.SysUtils.Supports(FServicesList.Items[AServiceGUID], AServiceGUID, AService)
  else
  begin
    Pointer(AService) := nil;
    Result := False;
  end;
end;

function TRfServices.SupportsService(const AServiceGUID: TGUID): Boolean;
begin
  Result := FServicesList.ContainsKey(AServiceGUID);
end;

class procedure TRfServices.Add(const AServiceGUID: TGUID; const AService: IInterface);
begin
  Current.AddService(AServiceGUID, AService);
end;

class procedure TRfServices.Remove(const AServiceGUID: TGUID);
begin
  if Assigned(FCurrent) then
    Current.RemoveService(AServiceGUID);
end;

class function TRfServices.Supports(const AServiceGUID: TGUID; out AService): Boolean;
begin
  Result := Assigned(FCurrent) and FCurrent.SupportsService(AServiceGUID, AService);
end;

initialization
finalization
  TRfServices.ReleaseCurrent;
end.
