# Authentifizierung und Autorisierung in Microservices mit JWT und definierten Schnittstellen

## Inhaltsverzeichnis

- [Authentifizierung und Autorisierung in Microservices mit JWT und definierten Schnittstellen](#authentifizierung-und-autorisierung-in-microservices-mit-jwt-und-definierten-schnittstellen)
  - [Inhaltsverzeichnis](#inhaltsverzeichnis)
  - [1. Einleitung](#1-einleitung)
  - [2. Grundlagen: Authentifizierung \& Autorisierung](#2-grundlagen-authentifizierung--autorisierung)
    - [Authentifizierung:](#authentifizierung)
    - [Autorisierung:](#autorisierung)
  - [3. JWT in ASP.NET Core WebAPI](#3-jwt-in-aspnet-core-webapi)
    - [Voraussetzungen:](#voraussetzungen)
    - [Implementierungsschritte:](#implementierungsschritte)
    - [Token-Erstellung:](#token-erstellung)
  - [4. API-Gateway mit Ocelot](#4-api-gateway-mit-ocelot)
    - [Beispielhafte `ocelot.json`-Konfiguration:](#beispielhafte-ocelotjson-konfiguration)
    - [Integration:](#integration)
  - [5. Definierte Schnittstellen: REST vs GraphQL vs gRPC](#5-definierte-schnittstellen-rest-vs-graphql-vs-grpc)
    - [REST:](#rest)
    - [GraphQL:](#graphql)
    - [gRPC:](#grpc)
    - [Fazit:](#fazit)
  - [6. Zusammenfassung \& Best Practices](#6-zusammenfassung--best-practices)
    - [Vorteile von JWT + Gateway:](#vorteile-von-jwt--gateway)
    - [Herausforderungen:](#herausforderungen)
    - [Best Practices:](#best-practices)
  - [7. Praktische Umsetzung (Demo)](#7-praktische-umsetzung-demo)
    - [Inhalte der Demo:](#inhalte-der-demo)
    - [Beispielablauf:](#beispielablauf)
    - [Fehlerbehandlung:](#fehlerbehandlung)
  - [8. Quellen](#8-quellen)

---

## 1. Einleitung

Moderne Softwarearchitekturen nutzen Microservices, um modulare, skalierbare und wartbare Systeme zu schaffen. Doch mit der Modularität kommt auch die Herausforderung: **Wie schützen wir unsere Services sicher und zentral?**

In dieser Präsentation zeigen wir praxisnah:

* Wie **JWT (JSON Web Tokens)** zur sicheren Authentifizierung und Autorisierung eingesetzt wird
* Wie ein **API-Gateway mit Ocelot** zentral schützt
* Wie **REST, GraphQL und gRPC** als Schnittstellen agieren können

> Zielgruppe: Entwickler mit Grundkenntnissen in ASP.NET Core

<p align="center">
  <img src="https://learn.microsoft.com/de-de/azure/architecture/microservices/images/gateway.png" alt="Microservice Architektur" width="600"/>
</p>
_Ein typisches Architekturmodell mit API-Gateway, Auth-Service und mehreren unabhängigen Microservices._  

*Abb. 1: Microservices mit Gateway, Identity & Services*


---

## 2. Grundlagen: Authentifizierung & Autorisierung

### Authentifizierung:

Bestätigung der Identität eines Benutzers (z. B. über Login mit Passwort).

### Autorisierung:

Zugriffssteuerung: Was darf ein authentifizierter Benutzer tun?

> Beispiel: Du loggst dich ein (Authentifizierung) und darfst dann nur deine Daten sehen (Autorisierung).

**Warum JWT?**

* Kompakt, JSON-basiert, einfach zu übertragen
* Kein Session-Management nötig
* Kann Signatur und Payload enthalten (z. B. Rollen)

<p align="center">
  <img src="https://fusionauth.io/img/shared/json-web-token.png" alt="JWT Flow" width="600"/>
</p>
_Ein typischer JWT-Flow bei Login, Token-Ausstellung und Zugriff auf geschützte Ressourcen._  

*Abb. 2: Aufbau eines JWT (Header, Payload, Signature)*


---

## 3. JWT in ASP.NET Core WebAPI

### Voraussetzungen:

* ASP.NET Core WebAPI-Projekt
* Datenbank (z. B. MongoDB)
* ASP.NET Core Identity für Benutzerverwaltung

### Implementierungsschritte:

1. Projekt anlegen (`dotnet new webapi`)
2. Benutzerregistrierung & Login mit Token-Erstellung
3. Speicherung der Benutzer in MongoDB
4. Absicherung durch `[Authorize]`

```csharp
[Authorize]
[HttpGet("/profile")]
public IActionResult GetUserProfile() => Ok("Zugriff erlaubt");
```

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

**Warum ein API-Gateway?**

* Zentraler Zugriffspunkt für alle Services
* Routing, Logging, Authentifizierung und mehr

### Beispielhafte `ocelot.json`-Konfiguration:

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
  ]
}
```

### Integration:

* Middleware einrichten mit `AddOcelot()`
* JWT Validierung im Gateway konfigurieren

<p align="center">
  <img src="https://fusionauth.io/img/articles/tokens-microservices-boundaries/extraction.png" alt="Gateway-Flow" width="600"/>
</p>
_Das API-Gateway prüft den JWT-Token und leitet bei Gültigkeit die Anfragen an geschützte Microservices weiter._  

*Abb. 3: Token-basierter Zugriff auf Microservices via Gateway*


---

## 5. Definierte Schnittstellen: REST vs GraphQL vs gRPC

### REST:

* Ressourcenbasiert (GET /users/1)
* Einfach, aber oft Overfetching

### GraphQL:

* Abfrage-Sprache, Client wählt Felder
* Vorteil: exakt das zurück, was gebraucht wird
* Nachteile: komplexere Einrichtung

```graphql
query {
  user(id: "1") {
    name
    email
  }
}
```

### gRPC:

* Binäres Protokoll, ideal für schnelle Microservice-Kommunikation
* Verwendet Protobuf statt JSON
* Vorteil: Performance

```protobuf
service UserService {
  rpc GetUser(UserRequest) returns (UserResponse);
}
```

### Fazit:

| Schnittstelle | Vorteil                    | Nachteil                  |
| ------------- | -------------------------- | ------------------------- |
| REST          | Einfach, weit verbreitet   | Over-/Underfetching       |
| GraphQL       | Flexibel, client-gesteuert | Server-Performance        |
| gRPC          | Schnell, typisiert         | Weniger browserfreundlich |

<p align="center">
  <img src="https://miro.medium.com/v2/resize:fit:1400/1*o4TgSCCvQgyE0OKsVSgQwg.png" alt="REST vs GraphQL vs gRPC" width="600"/>
</p>
_Die Grafik zeigt Unterschiede in Struktur, Anfrageverarbeitung und Antwortverhalten zwischen REST, GraphQL und gRPC._  

*Abb. 4: Vergleich der Schnittstellen*


---

## 6. Zusammenfassung & Best Practices

### Vorteile von JWT + Gateway:

* Skalierbare, modulare Absicherung
* Token überall einsetzbar (z. B. SPA, Mobile)
* Gateway entlastet Microservices

### Herausforderungen:

* Token-Verwaltung (z. B. Refresh Tokens)
* Schutz sensibler Daten im Payload
* Zugriffskontrolle über Rollen / Claims

### Best Practices:

* HTTPS erzwingen
* Token-Lebensdauer beschränken
* \[Authorize(Roles = "Admin")] für granulare Kontrolle
* Separate Auth-Service mit Refresh-Logik

---

## 7. Praktische Umsetzung (Demo)

> **Demo wird von \[Majd] umgesetzt und präsentiert.**

### Inhalte der Demo:

* Benutzerregistrierung & Login mit JWT
* Token-geschützte Endpunkte mit `[Authorize]`
* Test über Swagger / Postman

### Beispielablauf:

1. POST `/register` → Benutzer erstellen
2. POST `/login` → JWT erhalten
3. GET `/profile` → Nur mit Token zugänglich
4. Aufruf via Gateway `/api/user/profile`

### Fehlerbehandlung:

* Ungültiger Token: 401 Unauthorized
* Token abgelaufen: 403 Forbidden

---

## 8. Quellen

* [JWT.io – JSON Web Tokens](https://jwt.io/)
* [Microsoft Docs – JWT in ASP.NET Core](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/jwt)
* [gRPC vs REST vs GraphQL](https://www.telerik.com/blogs/grpc-vs-rest-vs-graphql)
* [MongoDB C# Docs](https://www.mongodb.com/docs/drivers/csharp/)

---

**Präsentation erstellt von:** *\[Mohamed Gebeili]* & *\[Majd Bayeh]*
**Modul:** Verteilte Systeme Programmieren
**Datum:** \[27.05.2025]

> **https://github.com/MbayehLLL/JWTDemo**
