{ *********************************************************************** }
{ Copyright (c) 2010-2013 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.Astronomy;

interface

uses System.SysUtils, System.Math;

type

  TEclipticPosition = record
    Longitude: Extended; // λ — екліптична довгота [deg] [0..360]
    Latitude: Extended;  // β — екліптична широта [deg] [-90..+90]
    Distance: Extended;  // r — відстань від центру AU

    /// <summary>Нормалізує довготу до [0..360]</summary>
    procedure Normalize;
  end;

  TAstronomy = class
  protected const
    ArcSecondsPerRadian = 60 * 60 * 180 / Pi;  // Кутових секунд у радіані
  public const
    /// <summary>
    /// Light-year - світловий рік
    /// Units: m
    /// </summary>
    LightYear = 9.4607304725808E+15;

    /// <summary>
    /// Astronomical unit - Астрономічна одиниця. Exact
    /// Units: m
    /// </summary>
    AstronomicalUnit = 1.495978707E+11;

    /// <summary>
    /// Parsec - Парсек. Exact. Parsec = ArcSecondsPerRadian * AstronomicalUnit
    /// Units: m
    /// </summary>
    Parsec = 3.08567758149137E+16;

    /// <summary>
    /// Earth radius. Mean(avg) = (2 * EarthRadiusEquatorial + EarthRadiusPolar) / 3
    /// Units: m
    /// </summary>
    EarthRadius           = 6371008.8;
    EarthRadiusEquatorial = 6378137.0; // Equatorial radius
    EarthRadiusPolar      = 6356752.3; // Polar radius

    /// <summary>
    /// SynodicMonth for J2000.0: 1.01.2000y 12:00 TT (Earth time)
    /// Units: days
    /// </summary>
    SynodicMonthJ2000 = 29.5305888531;
    /// <summary>
    /// Кількість днів у Юліанському столітті (фіксована астрономічна величина = 365.25 * 100)
    /// </summary>
    JulianCenturyDays = 36525.0;
  public
    /// <summary>
    /// Перетворює дату у Юліанські століття від епохи J2000.0 (T)
    /// </summary>
    class function JulianCenturies(const ADate: TDateTime): Double; static; inline;

    /// <summary>
    /// SynodicMonth for Data. тривалість місяця змінюється через вікові збурення, використовується формула Шапрон-Тозе та Шапрона (1988):
    /// Units: days
    /// </summary>
    class function SynodicMonth(const ADate: TDateTime): Double; static;

    /// <summary>
    /// Calculates signed Moon phase for given date.
    /// Signed Moon phase in range [-1..+1].
    /// Absolute value = fraction (0 = New Moon, 1 = Full Moon).
    /// Sign:
    ///   negative — waxing Moon (зростаючий),
    ///   positive — waning Moon (спадаючий).
    /// Based on Meeus algorithms (low precision, ~1°).
    /// </summary>
    class function PhaseMoon(const ADate: TDateTime): Extended; static;
  end;

implementation

function LMod(const Value, Modulo: Extended): Extended; inline // функція для нормалізації кутів
begin
  Result := Value - Modulo * Floor(Value / Modulo);
end;

function SinDeg(const X: Extended): Extended; inline;
begin
  Result := Sin(DegToRad(X));
end;

function CosDeg(const X: Extended): Extended; inline;
begin
  Result := Cos(DegToRad(X));
end;

{ TEclipticPosition }

procedure TEclipticPosition.Normalize;
begin
  Longitude := LMod(Longitude, 360.0);
end;

{ TAstronomy }

class function TAstronomy.JulianCenturies(const ADate: TDateTime): Double;
const
  // Дата J2000.0 (1 січня 2000 року, 12:00 за земним часом). В TDateTime 0 - це 30.12.1899, тому J2000.0 = 36526.5
  J2000_Epoch = 36526.5;
var
  DaysSinceJ2000: Double;
begin
  DaysSinceJ2000 := ADate - J2000_Epoch; // кількість днів від J2000.0
  Result := DaysSinceJ2000 / JulianCenturyDays; // Переводимо дні у Юліанські століття
end;

class function TAstronomy.SynodicMonth(const ADate: TDateTime): Double;
var
  T: Double;
begin
  T := JulianCenturies(ADate); // Переводимо дні у Юліанські століття
  // Обчислюємо значення за формулою Шапрона-Тозе
  // 29.5305888531 + 0.00000021621 * T-3.64*10^{-10}* T^2)де T — кількість юліанських століть від епохи J2000.0. 
  Result := SynodicMonthJ2000 + (0.00000021621 * T) - (3.64E-10 * Sqr(T));
end;

function SunMeeus(const T: Double): TEclipticPosition;
var
  L0, M, e, C: Extended;
begin
  // Середня довгота Сонця (градуси)
  L0 := 280.46646 + 36000.76983 * T + 0.0003032 * Sqr(T);
  // Середня аномалія Сонця (градуси)
  M := 357.52911 + 35999.05029 * T - 0.0001537 * Sqr(T);
  // Рівняння центру Сонця (C) в градусах
  C := (1.914602 - 0.004817 * T) * SinDeg(M) +
       (0.019993 - 0.000101 * T) * SinDeg(2 * M);

  Result.Longitude := L0 + C; // Істинна довгота в градусах [0..360]
  Result.Latitude := 0.0; // Сонце завжди в екліптиці
  e := 0.016708634 - 0.000042037 * T; // Ексцентриситет для дистанції
  Result.Distance := (1.000001018 * (1 - Sqr(e))) / (1 + e * CosDeg(M + C));
  Result.Normalize;
end;

function MoonMeeus(const T: Double): TEclipticPosition;
var
  D, M, MP, F, LP, HP: Extended;
begin
  // Базові аргументи (в градусах)
  LP := 218.31645 + 481267.88123 * T; // Середня довгота Місяця
  D  := 297.8502  + 445267.1114 * T;  // Середня елонгація
  M  := 357.5291  + 35999.0503 * T;   // Середня аномалія Сонця
  MP := 134.9634  + 477198.8675 * T;  // Середня аномалія Місяця
  F  := 93.2721   + 483202.0175 * T;   // Аргумент широти

  // Перетворюємо аргументи в радіани лише для функцій Sin/Cos
  // Довгота L = Середня довгота LP + головні періодичні збурення
  Result.Longitude := LP +
    6.288774 * SinDeg(MP) +
    1.274027 * SinDeg(2 * D - MP) +
    0.658314 * SinDeg(2 * D) +
    0.213618 * SinDeg(2 * MP) -
    0.185116 * SinDeg(M) -
    0.114332 * SinDeg(2 * F);

  // Широта
  Result.Latitude := 5.128122 * SinDeg(F) +
       0.280602 * SinDeg(MP + F) +
       0.277693 * SinDeg(MP - F) +
       0.173237 * SinDeg(2 * D - F);

  // Горизонтальний паралакс за Міусом (головні члени)
  HP := 0.950724 + 0.051818 * CosDeg(MP) + 0.009531 * CosDeg(2*D - MP);
  // Дистанція: (Радіус екватора / Sin(HP)) / AU, Оскільки обидва радіуси в метрах, результат буде чистим числом в AU
  Result.Distance := (TAstronomy.EarthRadiusEquatorial / SinDeg(HP)) / TAstronomy.AstronomicalUnit;
  Result.Normalize;
end;

class function TAstronomy.PhaseMoon(const ADate: TDateTime): Extended;
var
  T: Double;
  Sun, Moon: TEclipticPosition;
  S, D, CGam, SGam, DistRatio, Illum: Extended;
begin
  T := JulianCenturies(ADate);
  Sun := SunMeeus(T);
  Moon := MoonMeeus(T);

  D := Sun.Longitude - Moon.Longitude; // Різниця довгот (Елонгація)
  CGam := CosDeg(D) * CosDeg(Moon.Latitude); // Косинус кута між Сонцем і Місяцем для земного спостерігача (CGam)
  if CGam > 1.0 then CGam := 1.0 else if CGam < -1.0 then CGam := -1.0; // Обмеження для стабільності ArcCos/ArcTan
  DistRatio := Moon.Distance / Sun.Distance; // Розрахунок фазового кута (i) — кут "Сонце-Місяць-Земля", Moon.Distance і Sun.Distance в одних одиницях AU
  SGam := Sqrt(1.0 - CGam*CGam);
  S := RadToDeg(ArcTan2(SGam, DistRatio - CGam)); // Обчислюємо фазовий кут (S)

  Illum := (1 + CosDeg(S)) / 2; // ФОРМУЛА ОСВІТЛЕНОСТІ (k) Результат від 0.0 (Молодик) до 1.0 (Повня)

  // Додаємо знак для зручності (Waning/Waxing) Нормалізуємо D до [0..360]
  D := LMod(D, 360.0);
  if D > 180.0 then
    Result := -Illum // Місяць спадає
  else
    Result := Illum; // Місяць росте
end;

end.
