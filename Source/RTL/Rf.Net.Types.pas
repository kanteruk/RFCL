{ *********************************************************************** }
{ Copyright (c) 2016-2017 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.Net.Types;

interface

{$SCOPEDENUMS ON}

uses
  System.Types, System.SysUtils, System.Net.URLClient, System.NetEncoding,
  Rf.Types;

type
  TURI = System.Net.URLClient.TURI;
  TURIHelper = record helper for TURI
  public const
    DEF_PROTOCOL_DELIMITER = '://';

    SCHEME_FTP   = 'ftp';
    SCHEME_FTPS  = 'ftps';
    SCHEME_SFTP  = 'sftp';
    SCHEME_FTPES = 'ftpes';

    SCHEME_FILE = 'file'; // 'file://'  example  file://host/path or file:///path
    SCHEME_DATA = 'data'; // 'data:'    example  data:[<media type>][;base64],<data>
  public
    {$IF RTLVersion >= 36}
    /// <summary>
    /// AddParameter - виправлена версія бо в новому дельфі 12 в TNetEncoding.URL.EncodeQuery
    /// додали по дефолту заміну символу %
    /// Також має бути встановлений патч 1
    /// На майбутнє перевірити чи в нових патчах це профіксять
    /// </summary>
    procedure AddParameter(const AName, AValue: string);
    {$ENDIF}
    class function IsWebPath(const APath: string): Boolean; static;
  end;

  {$REGION 'TUserAgent'}
  TUserAgent = type string;
  TUserAgentHelper = record helper for TUserAgent
  private
    class function GetDefault: string; static;
  public
    class property Default: string read GetDefault;
  end;
  {$ENDREGION}

  THTTPStatusCode = type Integer;
  THTTPStatusCodeHelper = record helper for THTTPStatusCode
  public const
    Empty               = THTTPStatusCode(0);
    // 1xx informational response
    Continue            = THTTPStatusCode(100);
    SwitchingProtocols  = THTTPStatusCode(101);
    Processing          = THTTPStatusCode(102);
    EarlyHints          = THTTPStatusCode(103);
    // 2xx success
    OK                  = THTTPStatusCode(200);
    Created             = THTTPStatusCode(201);
    Accepted            = THTTPStatusCode(202);
    NonAuthoritativeInformation = THTTPStatusCode(203);
    NoContent           = THTTPStatusCode(204);
    // 3xx redirection
    MultipleChoices     = THTTPStatusCode(300);
    MovedPermanently    = THTTPStatusCode(301);
    Found               = THTTPStatusCode(302);
    SeeOther            = THTTPStatusCode(303);
    // 4xx client errors
    BadRequest          = THTTPStatusCode(400);
    Unauthorized        = THTTPStatusCode(401);
    PaymentRequired     = THTTPStatusCode(402);
    Forbidden           = THTTPStatusCode(403);
    NotFound            = THTTPStatusCode(404);
    TooManyRequests     = THTTPStatusCode(429);
    // 5xx server errors
    InternalServerError = THTTPStatusCode(500);
    NotImplemented      = THTTPStatusCode(501);
  public
    function IsEmpty: Boolean;
    function Is2xx: Boolean; inline; // 2xx code
    function IsSuccessful: Boolean;
  end;

  TPortNumber = type Integer;
  TPortNumberHelper = record helper for TPortNumber
  public const
    DEF_FTP_PORT   = TPortNumber(21);
    DEF_SSH_PORT   = TPortNumber(22);
    DEF_SMTP_PORT  = TPortNumber(587);

    DEF_HTTP_PROXY_SERVER_PORT = TPortNumber(8080);
    DEF_FTP_PROXY_SERVER_PORT  = TPortNumber(8021);

    DEF_MYSQL_PORT        = TPortNumber(3306);
  public
    function ToString: string;
  end;

const
  // URL Schemas constants (LowerCase!)
  sHttpPrefix  = TURI.SCHEME_HTTP + TURI.DEF_PROTOCOL_DELIMITER;
  sHttpsPrefix = TURI.SCHEME_HTTPS + TURI.DEF_PROTOCOL_DELIMITER;
  sFTPPrefix   = TURI.SCHEME_FTP + TURI.DEF_PROTOCOL_DELIMITER;
  sFTPSPrefix  = TURI.SCHEME_FTPS + TURI.DEF_PROTOCOL_DELIMITER;
  sSFTPPrefix  = TURI.SCHEME_SFTP + TURI.DEF_PROTOCOL_DELIMITER;
  sFTPESPrefix = TURI.SCHEME_FTPES + TURI.DEF_PROTOCOL_DELIMITER;

type
  THostNames = record
  const
    Localhost     = 'localhost';
    LocalhostIP   = '127.0.0.1';
    LocalhostIPv6 = '::1';
  end;

implementation

{ TUserAgentHelper }

class function TUserAgentHelper.GetDefault: string;
begin
  Result :=
    //* Browser Info
    'Mozilla/5.0' +
    //* System Info
    ' (' +
    {$IFDEF MSWINDOWS}
    'Windows NT ' + TOSVersion.Major.ToString + '.' + TOSVersion.Minor.ToString +
    IfThen(TOSVersion.Architecture in [arIntelX64], '; Win64; x64', '') +
    {$ENDIF}
    {$IFDEF POSIX}
      {$IFDEF MACOS} 'Macintosh; Intel ' + {$ENDIF}
      {$IFDEF ANDROID} 'Linux; Android ' + {$ENDIF}
      TOSVersion.Name + ' ' + TOSVersion.Major.ToString + '_' + TOSVersion.Minor.ToString + '_' + TOSVersion.ServicePackMajor.ToString +
    {$ENDIF}
    ') ' +
    //* Platform
    ' AppleWebKit/537.36 (KHTML, like Gecko)' +
    //* Extension
    ' Chrome/107.0.0.0 Safari/537.36';
end;

{ THTTPStatusCodeHelper }

function THTTPStatusCodeHelper.IsEmpty: Boolean;
begin
  Result := (Self = Empty);
end;

function THTTPStatusCodeHelper.Is2xx: Boolean;
begin
  Result := (Self >= 200) and (Self <= 299);
end;

function THTTPStatusCodeHelper.IsSuccessful: Boolean;
begin
  Result := Is2xx;
end;

{ TPortNumberHelper }

function TPortNumberHelper.ToString: string;
begin
  Result := Integer(Self).ToString;
end;

{ TURIHelper }

class function TURIHelper.IsWebPath(const APath: string): Boolean;
begin
  Result := APath.StartsWith(sHttpsPrefix) or APath.StartsWith(sHttpPrefix);
end;

{$IF RTLVersion >= 36}
procedure TURIHelper.AddParameter(const AName, AValue: string);
var
  Len: Integer;
  LParams: TURIParameters;
begin
  LParams := Params;
  Len := Length(LParams);
  SetLength(LParams, Len + 1);
  LParams[Len].Name := AName;
  LParams[Len].Value := AValue;
  Params := LParams; // this cal SetParams and apply TryEncode for each params and rebuild query
end;
{$ENDIF}

end.
