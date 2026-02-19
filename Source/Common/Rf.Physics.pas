{ *********************************************************************** }
{ Copyright (c) 2006-2019 Digital Lion Solutions. All rights rezerved.    }
{ Author: Ruslan Kanteruk                                                 }
{ E-Mail: kanteruk@gmail.com                                              }
{ *********************************************************************** }

unit Rf.Physics;

interface

type

  TPhysConst = class
  public const
    /// <summary>
    /// Gravitation Const - Гравітаційна стала. (official value CODATA 2018–2022)
    /// Units: m3⋅kg−1⋅s−2.
    /// </summary>
    Gravitation = 6.67430E-11;

    /// <summary>
    /// Acceleration of the free falling - Прискорення вільного падіння на Землі
    /// Реальне значення прискорення вільного падіння на поверхні Землі:
    /// g = 9.780327 * [ 1 + 0.0053024 * sin²(f) − 0.0000058 * sin²(2f)] − 3.086E−6 * h,
    /// де f — географічна широта точки, h — висота над рівнем моря.
    /// </summary>
    GravityAcceleration = 9.80665 ; // м/с^2

    // Прискорення на інших планетах:
    GravityAccelerationMoon    = 1.62;
    GravityAccelerationMercury = 3.70;
    GravityAccelerationVenus   = 8.88;
    GravityAccelerationMars    = 3.86;
    GravityAccelerationJupiter = 23.95;
    GravityAccelerationSaturn  = 9.74;
    GravityAccelerationUranus  = 7.51;
    GravityAccelerationNeptune = 11.0;
    GravityAccelerationSun     = 273.8;

    /// <summary>
    /// Elementary Electron Charge - Елементарний заряд електрона
    /// </summary>
    ElectronCharge = 1.602176487E-19; // Кл = 1.602176487(40)E-19

    /// <summary>
    /// Маса електрона
    /// Units: kg.
    /// </summary>
    ElectronMass = 9.10938215E-31; // кг

    /// <summary>
    /// Маса протона
    /// Units: kg.
    /// </summary>
    ProtonMass = 1.672621637E-27; // кг

    /// <summary>
    /// Маса нейтрона
    /// Units: kg.
    /// </summary>
    NeutronMass = 1.674927211E-27; // кг

    /// <summary>
    /// Електрична стала
    /// </summary>
    Electric = 8.854187817620E-12; // Ф/м

    /// <summary>
    /// Atomic mass unit - Атомна одиниця маси а.о.м
    /// Units: kg.
    /// </summary>
    AMU = 1.66053906660E-27; // кг

    /// <summary>
    /// Speed of light in vacuum. Exact(CODATA 2022)
    /// Units: m/s.
    /// </summary>
    SpeedOfLight = 299792458;

    /// <summary>
    /// Стала планка.
    /// Units: J·s.
    /// </summary>
    Planck = 6.62607015E-34;

    /// <summary>
    /// Стала Фарадея.
    /// Units: C/mol.
    /// </summary>
    Faraday = 96485.33212;

    /// <summary>
    /// Avogadro constant - Число Авогадро.
    /// Units: 1/mol.
    /// </summary>
    Avogadro = 6.02214076E23; // 1/моль

    /// <summary>
    /// Boltzmann Const - Стала Больцмана
    /// Units: J/K.
    /// </summary>
    Boltzmann = 1.380649E-23; // Дж/К

    /// <summary>
    /// Stefan–Boltzmann Const - Стала Стефана-Больцмана
    /// Units: W·m−2·K−4.
    /// </summary>
    StefanBoltzmann = 5.670374419E-8; // Вт · м^-2 · K^-4

    /// <summary>
    /// Gas constant - Універсальна газова стала
    /// Units: J/(mol·K)
    /// </summary>
    Gas = 8.31446261815; // Дж/(моль·К)
  end;

  TPhysics = class
  public
    /// <summary>
    /// Гравітаційна сила: F = G * m1 * m2 / r^2
    /// Units: m, kg
    /// </summary>
    class function ForceGravitationEx(const Mass1, Mass2, R: Extended): Extended; static; inline;

    /// <summary>
    /// Сила тяжіння: F = m*g
    /// </summary>
    class function ForceGravitation(const Mass, Gravity: Extended): Extended; static; inline;
    class function ForceGravitationOnEarth(const Mass: Extended): Extended; static; inline;

    /// <summary>
    /// Density = Густина = m/V
    /// Units: kg / m3
    /// </summary>
    class function Density(const Mass, Volume: Extended): Extended; static; inline;

    /// <summary>
    /// Сила Ахімеда: F = p*V*g
    /// Volume - обєм
    /// Density - густина рідини
    /// Gravity - прискорення вільного падіння
    /// </summary>
    class function ForceArchimedes(const Volume, Density, Gravity: Extended): Extended; static; inline;
    class function ForceArchimedesOnEarth(const Volume, Density: Extended): Extended; static; inline;

    /// <summary>
    /// FallTime = Час падіння = Sqrt(2h/g) (sec.)
    /// </summary>
    class function FallTime(const Height, Gravity: Extended): Extended; static; inline;
    class function FallTimeOnEarth(const Height: Extended): Extended; static; inline;
  end;


implementation

{ TPhysics }

class function TPhysics.ForceGravitationEx(const Mass1, Mass2, R: Extended): Extended;
begin
  Result := TPhysConst.Gravitation * Mass1 * Mass2 / Sqr(R);
end;

class function TPhysics.ForceGravitation(const Mass, Gravity: Extended): Extended;
begin
  Result := Mass * Gravity;
end;

class function TPhysics.ForceGravitationOnEarth(const Mass: Extended): Extended;
begin
  Result := ForceGravitation(Mass, TPhysConst.GravityAcceleration);
end;

class function TPhysics.Density(const Mass, Volume: Extended): Extended;
begin
  Result := Mass / Volume;
end;

class function TPhysics.ForceArchimedes(const Volume, Density, Gravity: Extended): Extended;
begin
  Result := Volume * Density * Gravity;
end;

class function TPhysics.ForceArchimedesOnEarth(const Volume, Density: Extended): Extended;
begin
  Result := ForceArchimedes(Volume, Density, TPhysConst.GravityAcceleration);
end;

class function TPhysics.FallTime(const Height, Gravity: Extended): Extended;
begin
  Result := Sqrt(2 * Height / Gravity);
end;

class function TPhysics.FallTimeOnEarth(const Height: Extended): Extended;
begin
  Result := FallTime(Height, TPhysConst.GravityAcceleration)
end;

end.