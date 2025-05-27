# Authentifizierung und Autorisierung in Microservices mit JWT und definierten Schnittstellen

## Inhaltsverzeichnis

- [Authentifizierung und Autorisierung in Microservices mit JWT und definierten Schnittstellen](#authentifizierung-und-autorisierung-in-microservices-mit-jwt-und-definierten-schnittstellen)
  - [Inhaltsverzeichnis](#inhaltsverzeichnis)
  - [1. Einleitung](#1-einleitung)
  - [2. Grundlagen: Authentifizierung \& Autorisierung](#2-grundlagen-authentifizierung--autorisierung)
    - [Authentifizierung](#authentifizierung)
    - [Autorisierung](#autorisierung)
    - [Warum JWT?](#warum-jwt)
  - [3. JWT in ASP.NET Core WebAPI](#3-jwt-in-aspnet-core-webapi)
    - [Voraussetzungen:](#voraussetzungen)
    - [Implementierungsschritte:](#implementierungsschritte)
  - [4. API-Gateway mit Ocelot](#4-api-gateway-mit-ocelot)
    - [Warum ein API-Gateway?](#warum-ein-api-gateway)
    - [Warum Ocelot?](#warum-ocelot)
    - [Beispielhafte `ocelot.json`-Konfiguration](#beispielhafte-ocelotjson-konfiguration)
    - [Integration in ASP.NET Core](#integration-in-aspnet-core)
      - [Pakete installieren:](#pakete-installieren)
      - [Middleware registrieren:](#middleware-registrieren)
      - [Pipeline konfigurieren:](#pipeline-konfigurieren)
    - [Wie funktioniert die Authentifizierung im Gateway?](#wie-funktioniert-die-authentifizierung-im-gateway)
  - [5. Definierte Schnittstellen: REST vs GraphQL vs gRPC](#5-definierte-schnittstellen-rest-vs-graphql-vs-grpc)
    - [REST](#rest)
    - [GraphQL](#graphql)
    - [gRPC](#grpc)
    - [Wann verwendet man was?](#wann-verwendet-man-was)
  - [6. Praktische Umsetzung (Demo)](#6-praktische-umsetzung-demo)
  - [Inhalte der Demo](#inhalte-der-demo)
  - [7. Zusammenfassung](#7-zusammenfassung)
    - [Vorteile von JWT + Gateway](#vorteile-von-jwt--gateway)
    - [Herausforderungen in der Praxis](#herausforderungen-in-der-praxis)
  - [8. Quellen](#8-quellen)

---

## 1. Einleitung

Microservices sind heute ein gängiger Architekturansatz, um komplexe Software modular, skalierbar und wartbar zu gestalten. Jeder Service übernimmt dabei eine klar abgegrenzte Aufgabe und kann unabhängig entwickelt und betrieben werden.

Mit dieser Dezentralisierung entsteht jedoch eine neue Herausforderung:  
**Wie kann sichergestellt werden, dass nur berechtigte Benutzer auf bestimmte Services zugreifen dürfen – ohne eine zentrale Sitzung oder monolithische Benutzerverwaltung?**

Die Lösung liegt in der Kombination aus:

- **JWT (JSON Web Tokens):** Ein kompaktes, digitales Token, das die Identität und Rechte eines Benutzers enthält – unabhängig überprüfbar und ideal für verteilte Systeme.
- **API-Gateway (z. B. Ocelot):** Eine zentrale Komponente, die eingehende Anfragen prüft, authentifiziert und dann gezielt an die internen Microservices weiterleitet.

Diese Präsentation zeigt praxisnah:

- Wie man **JWT in ASP.NET Core WebAPI** integriert
- Wie man mit **Ocelot ein API-Gateway** aufsetzt und absichert
- Welche Rolle **REST, GraphQL und gRPC** als Schnittstellenprotokolle spielen

> Zielgruppe: Entwickler mit Grundkenntnissen in ASP.NET Core und Interesse an sicherer Microservice-Kommunikation

<p align="center">
  <img src="https://learn.microsoft.com/de-de/azure/architecture/microservices/images/gateway.png" alt="Microservice Architektur" width="600"/>
</p>
_Ein typisches Architekturmodell mit API-Gateway, Auth-Service und mehreren unabhängigen Microservices._  

*Abb. 1: Microservices mit Gateway, Identity & Services*


---

## 2. Grundlagen: Authentifizierung & Autorisierung

In modernen Webanwendungen – insbesondere in verteilten Systemen mit Microservices – sind **Authentifizierung** und **Autorisierung** zwei zentrale Sicherheitsmechanismen, die strikt voneinander getrennt betrachtet werden sollten.

### Authentifizierung

Die **Authentifizierung** überprüft, ob der Benutzer tatsächlich derjenige ist, für den er sich ausgibt.

Typische Verfahren:
- Benutzername + Passwort
- Zwei-Faktor-Authentifizierung (z. B. SMS-Code oder Authenticator-App)
- OAuth-Login (z. B. via Google oder GitHub)

Ergebnis: Der Benutzer ist **eindeutig identifiziert** – und erhält z. B. ein Token, das seine Identität bestätigt.

### Autorisierung

Die **Autorisierung** regelt, **welche Aktionen** ein bereits authentifizierter Benutzer **durchführen darf**.

Beispiele:
- Ein „normaler Benutzer“ darf nur seine eigenen Daten sehen.
- Ein „Admin“ darf auch andere Benutzer verwalten oder löschen.

Das System prüft dabei Berechtigungen auf Basis von:
- **Rollen** (z. B. `User`, `Admin`)
- **Claims** (z. B. `DarfDatenExportieren: true`)

> Beispiel: Du loggst dich ein (Authentifizierung) und darfst danach nur deine eigenen Daten sehen (Autorisierung).

<p align="center">
  <img src="https://www.unidy.io/images/blog/auth-vs-authz.png" alt="Microservice Architektur" width="600"/>
</p>

---

### Warum JWT?

**JWT (JSON Web Token)** ist ein offener Standard (RFC 7519) zur sicheren Übertragung von Claims zwischen zwei Parteien – ideal für Microservices.

**Vorteile:**

- **Kompakt:** Kann leicht über HTTP-Header gesendet werden
- **Signiert:** Manipulationssicher durch digitale Signatur
- **Selbstbeschreibend:** Beinhaltet alle nötigen Informationen (z. B. User-ID, Rolle)
- **Stateless:** Kein Session-Management nötig – der Server speichert keine Sitzungsdaten

Ein JWT besteht aus drei Teilen:
1. **Header** – Typ & Signaturalgorithmus (z. B. HMAC SHA256)
2. **Payload** – Nutzdaten (Claims)
3. **Signature** – Schutz gegen Manipulation

> Dadurch eignet sich JWT perfekt zur Weitergabe von Benutzeridentitäten an unabhängige Microservices – ohne zentralen Zustand.

<p align="center">
  <img src="https://fusionauth.io/img/shared/json-web-token.png" alt="JWT Flow" width="600"/>
</p>
_Ein typischer JWT-Flow bei Login, Token-Ausstellung und Zugriff auf geschützte Ressourcen._  

*Abb. 2: Aufbau eines JWT (Header, Payload, Signature)*


---

## 3. JWT in ASP.NET Core WebAPI

In einer verteilten Microservice-Umgebung ist es wichtig, dass sich Benutzer zentral anmelden können und ihre Identität bei allen folgenden API-Aufrufen nachweisbar ist. Genau hier setzt JWT (JSON Web Token) an: Nach erfolgreichem Login erzeugt der Server ein Token, das alle notwendigen Informationen über den Benutzer enthält – und das vom Client bei jedem weiteren Request mitgeschickt wird.

---

### Voraussetzungen:

Um JWT erfolgreich in einer ASP.NET Core WebAPI umzusetzen, benötigst du:

* Ein ASP.NET Core WebAPI-Projekt
* Eine Datenbank (z. B. MongoDB, SQL Server) zur Speicherung von Benutzerdaten
* ASP.NET Core Identity zur Verwaltung von Benutzern, Rollen und Authentifizierung
* Eine JWT-Konfiguration in `appsettings.json` mit Angaben wie:
  - Schlüssel (Secret)
  - Aussteller (Issuer)
  - Empfänger (Audience)
  - Gültigkeitsdauer des Tokens

Diese Informationen werden beim Token-Handling verwendet, um es sicher und gültig zu halten.

---

### Implementierungsschritte:

Die grundlegenden Schritte zur Integration von JWT sind:

1. **Projekt erstellen:** z. B. mit `dotnet new webapi`
2. **Benutzerregistrierung und Login** implementieren
3. **JWT erstellen und an den Client zurückgeben**
4. **Benutzer in einer Datenbank speichern** (z. B. MongoDB)
5. **API-Endpunkte mit `[Authorize]` absichern**

Dadurch kann jeder nachfolgende Request auf geschützte Daten nur dann erfolgen, wenn das mitgeschickte Token gültig ist.

<p align="center">
  <img src="https://i.ytimg.com/vi/1geu1ElEdII/maxresdefault.jpg" alt="Microservice Architektur" width="600"/>
</p>

**Beispiel zur Absicherung eines Endpunkts:**

```csharp
[Authorize]
[HttpGet("/profile")]
public IActionResult GetUserProfile() => Ok("Zugriff erlaubt");

### Token-Erstellung:

```csharp
var token = new JwtSecurityToken(
    issuer: _config["Jwt:Issuer"],
    audience: _config["Jwt:Audience"],
    expires: DateTime.Now.AddHours(1),
    claims: claims,
    signingCredentials: creds
);
```

---

## 4. API-Gateway mit Ocelot

Ein **API-Gateway** ist ein zentrales Element in einer Microservice-Architektur. Es fungiert als „Türsteher“ zwischen externen Clients (z. B. Browser oder Mobile Apps) und den internen Microservices. Statt jeden Dienst direkt anzusprechen, gehen alle Anfragen **zuerst an das Gateway** – das entscheidet, ob und wohin sie weitergeleitet werden.

<p align="center">
  <img src="https://media.licdn.com/dms/image/v2/C4D12AQGyoJLmgKbE9Q/article-cover_image-shrink_600_2000/article-cover_image-shrink_600_2000/0/1541855696512?e=2147483647&v=beta&t=-CCYFlEXIa9sQ_w8WIgHzoZK4Vj4xK_ffFu2-Y1OSbk" alt="Microservice Architektur" width="600"/>
</p>

---

### Warum ein API-Gateway?

Ein Gateway bietet viele Vorteile:

- **Zentrale Authentifizierung**: JWT-Token wird nur hier geprüft – die Microservices bleiben schlank
- **Routing**: Leitet Anfragen je nach URL, Methode oder Header an den richtigen Dienst weiter
- **Logging & Monitoring**: Einfachere Protokollierung und Fehlerverfolgung
- **Sicherheit**: Blockieren unerwünschter Anfragen, Rate-Limiting oder IP-Filterung
- **Anpassung**: Übersetzung von Pfaden, Headern oder HTTP-Methoden

> In vielen Szenarien ersetzt ein API-Gateway einen klassischen Load Balancer und bietet gleichzeitig Sicherheits- und Kontrollfunktionen.

---

### Warum Ocelot?

[Ocelot](https://ocelot.readthedocs.io/en/latest/) ist ein leichtgewichtiges Open-Source API-Gateway für das .NET-Ökosystem. Es ist einfach einzurichten, vollständig in ASP.NET Core integrierbar und speziell für Microservice-Szenarien ausgelegt.

Es unterstützt u. a.:

- JWT-Authentifizierung
- Weiterleitung von Anfragen (Reverse Proxy)
- Transformation von Headern, Pfaden und Abfragen
- Caching, Retry-Logik und Load Balancing

---

### Beispielhafte `ocelot.json`-Konfiguration

```json
{
  "Routes": [
    {
      "DownstreamPathTemplate": "/user/{everything}",
      "UpstreamPathTemplate": "/api/user/{everything}",
      "AuthenticationOptions": {
        "AuthenticationProviderKey": "Bearer",
        "AllowedScopes": []
      }
    }
  ],
  "GlobalConfiguration": {
    "BaseUrl": "https://localhost:5001"
  }
}
```

- **UpstreamPathTemplate**: Der Pfad, der vom Client aufgerufen wird  
- **DownstreamPathTemplate**: Der interne Pfad im Microservice  
- **AuthenticationProviderKey**: Gibt an, dass JWT-Authentifizierung aktiviert ist

---

### Integration in ASP.NET Core

Damit Ocelot funktioniert, sind nur wenige Schritte im `Program.cs` (oder `Startup.cs`) notwendig:

#### Pakete installieren:

- `Ocelot`
- `Microsoft.AspNetCore.Authentication.JwtBearer`

#### Middleware registrieren:

```csharp
builder.Services.AddAuthentication("Bearer")
    .AddJwtBearer("Bearer", options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            // Weitere Einstellungen wie Issuer, Audience, etc.
        };
    });

builder.Services.AddOcelot();
```

#### Pipeline konfigurieren:

```csharp
app.UseAuthentication();
app.UseAuthorization();
await app.UseOcelot();
```

---

### Wie funktioniert die Authentifizierung im Gateway?

- Das Gateway liest den JWT-Token aus dem `Authorization`-Header der Anfrage.
- Es prüft:
  - die Signatur,
  - das Ablaufdatum (Gültigkeit),
  - sowie optional Claims oder Rollen.
- Nur bei erfolgreicher Prüfung wird die Anfrage an den Ziel-Microservice weitergeleitet.
- Andernfalls gibt Ocelot sofort eine Fehlermeldung zurück, z. B.:
  - `401 Unauthorized` (kein Token oder ungültig)
  - `403 Forbidden` (Token gültig, aber unzureichende Berechtigungen)

> **Vorteil:** Die Microservices selbst bleiben schlank – sie müssen keine Authentifizierung mehr implementieren. Alles läuft zentral über das Gateway.


<p align="center">
  <img src="https://fusionauth.io/img/articles/tokens-microservices-boundaries/extraction.png" alt="Gateway-Flow" width="600"/>
</p>
Das API-Gateway prüft den JWT-Token und leitet bei Gültigkeit die Anfragen an geschützte Microservices weiter.

*Abb. 3: Token-basierter Zugriff auf Microservices via Gateway*


---

## 5. Definierte Schnittstellen: REST vs GraphQL vs gRPC

In Microservice-Architekturen müssen Services miteinander kommunizieren – oft über definierte Schnittstellen. Die Wahl der Schnittstelle beeinflusst maßgeblich die Flexibilität, Geschwindigkeit und Effizienz der Kommunikation.

Hier vergleichen wir drei weit verbreitete Ansätze: **REST**, **GraphQL** und **gRPC**.

<p align="center">
  <img src="https://miro.medium.com/v2/resize:fit:1400/1*o4TgSCCvQgyE0OKsVSgQwg.png" alt="REST vs GraphQL vs gRPC" width="600"/>
</p>
Die Grafik zeigt Unterschiede in Struktur, Anfrageverarbeitung und Antwortverhalten zwischen REST, GraphQL und gRPC.  

*Abb. 4: Vergleich der Schnittstellen*

---

### REST

REST (Representational State Transfer) ist der Klassiker unter den Webschnittstellen. Es arbeitet über das HTTP-Protokoll und verwendet standardisierte Methoden wie `GET`, `POST`, `PUT` und `DELETE`, um auf **Ressourcen** zuzugreifen.

Beispiel:  
`GET /users/1` → Gibt den Benutzer mit der ID 1 zurück

**Vorteile:**
- Einfach zu verstehen und zu implementieren
- Breit unterstützt in allen Sprachen und Tools
- Ideal für öffentliche APIs

**Nachteile:**
- **Overfetching:** Es werden mehr Daten geladen, als benötigt
- **Underfetching:** Mehrere Requests nötig, um alles zu bekommen

---

### GraphQL

GraphQL ist eine Abfrage-Sprache von Facebook. Anders als bei REST definiert der Server keine fixen Endpunkte – stattdessen stellt der **Client gezielt die Felder zusammen**, die er benötigt.

Beispiel:

```graphql
query {
  user(id: "1") {
    name
    email
  }
}
```

**Vorteile:**
- Der Client bekommt **nur die Daten**, die er wirklich braucht
- Ideal für komplexe Datenstrukturen (z. B. verschachtelte Objekte)
- Flexibel bei Änderungen am Frontend

**Nachteile:**
- Komplexere Einrichtung am Server
- Performance-Tuning schwieriger
- Keine native Unterstützung in Browsern

---

### gRPC

gRPC (Google Remote Procedure Call) ist ein modernes, binäres Protokoll, das auf HTTP/2 und Protocol Buffers (Protobuf) basiert. Es ist besonders für die **interne Kommunikation zwischen Microservices** gedacht.

Beispiel:

```protobuf
service UserService {
  rpc GetUser(UserRequest) returns (UserResponse);
}
```

**Vorteile:**
- Sehr **schnell und effizient** durch binäre Übertragung
- Unterstützt **Streaming**, bidirektionale Kommunikation
- Typensicherheit durch `.proto`-Definitionen

**Nachteile:**
- Nicht direkt browserfähig (kein JSON)
- Debugging auf Netzwerkebene schwieriger
- Höhere Einstiegshürde

---

### Wann verwendet man was?

| Schnittstelle | Vorteile                             | Nachteile                            | Geeignet für...                              |
|---------------|--------------------------------------|---------------------------------------|----------------------------------------------|
| **REST**      | Einfach, weit verbreitet              | Overfetching / viele Einzelanfragen   | Öffentliche APIs, einfache CRUD-Services     |
| **GraphQL**   | Flexibel, genau abgestimmte Abfragen | Komplexer, evtl. leistungshungrig     | Frontend-getriebene APIs, Single-Page-Apps   |
| **gRPC**      | Schnell, ressourcenschonend          | Nicht browserfähig, höherer Aufwand   | Interne Kommunikation zwischen Services      |


---

## 6. Praktische Umsetzung (Demo)

> **Demo wird von \[Majd] umgesetzt und präsentiert.**

## Inhalte der Demo
 
- **Benutzerregistrierung & Login**: Erstellen eines Benutzers und Erhalt eines JSON Web Tokens (JWT).
- **Geschützte Endpunkte**: Zugriff auf Endpunkte nur mit gültigem Token via `[Authorize]`.
- **Swagger-Tests**: Interaktives Testen der API in der Swagger-UI.

---

## 7. Zusammenfassung

Nach der theoretischen Einführung und der praktischen Umsetzung ist es wichtig, einen Blick auf die langfristige Wartbarkeit und Sicherheit der Architektur zu werfen. Die Kombination aus **JWT-Authentifizierung** und einem **zentralen API-Gateway** ist heute Standard in modernen Microservice-Systemen – aber nur, wenn sie richtig implementiert und abgesichert wird.

---

### Vorteile von JWT + Gateway

- **Skalierbar & modular:** Jeder Microservice kann unabhängig validieren, ob ein Benutzer berechtigt ist – ohne zentrale Sessionverwaltung.
- **Flexibel einsetzbar:** JWT funktioniert in Web-Apps (SPA), Mobile Apps, Desktop-Anwendungen oder sogar IoT-Geräten.
- **Zentrale Kontrolle:** Das Gateway übernimmt Authentifizierung und Weiterleitung – die Microservices bleiben schlank und fokussiert.
- **Schneller Zugriff:** Keine ständige Datenbankabfrage – alle nötigen Infos stehen direkt im Token.
- **Stateless:** Kein Session-Handling nötig, ideal für Lastverteilung und horizontale Skalierung.

---

### Herausforderungen in der Praxis

Auch wenn JWT viele Vorteile bringt, gibt es typische Stolperfallen:

- **Token-Verwaltung:** Zugriffstoken laufen irgendwann ab – hier braucht man ein Konzept für **Refresh Tokens**.
- **Sensibler Payload:** Daten im Token (auch wenn Base64-kodiert) sind nicht verschlüsselt. Vertrauliche Informationen (z. B. Adresse, Rollenlogik) gehören nicht hinein.
- **Token-Diebstahl:** Wenn ein Token entwendet wird, kann es missbraucht werden – vor allem bei langer Gültigkeit.
- **Rollenkontrolle:** Wer darf was? Diese Frage muss konsequent über Claims oder Rollen geregelt werden.
- **Token-Invalidierung:** JWTs sind stateless – einmal ausgestellt, kann man sie nicht einfach „widerrufen“ (z. B. bei Logout), es sei denn, man speichert sie serverseitig in einer Blacklist.

---

## 8. Quellen

* [JWT.io – JSON Web Tokens](https://jwt.io/)
* [Microsoft Docs – JWT in ASP.NET Core](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/jwt)
* [gRPC vs REST vs GraphQL](https://www.telerik.com/blogs/grpc-vs-rest-vs-graphql)
* [MongoDB C# Docs](https://www.mongodb.com/docs/drivers/csharp/)

---

<p align="center">
  <img src="https://www.meme-arsenal.com/memes/36b7ba3dfe1a6c5c8411353961b5b185.jpg" width="600"/>
</p>

**Präsentation erstellt von:** *\[Mohamed Gebeili]* & *\[Majd Bayeh]*
**Modul:** Verteilte Systeme Programmieren
**Datum:** \[27.05.2025]

> **https://github.com/MbayehLLL/JWTDemo**
