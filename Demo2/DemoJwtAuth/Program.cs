using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// 1) JWT-Einstellungen aus Konfiguration lesen
var jwt = builder.Configuration.GetSection("JwtSettings");
var key = Encoding.UTF8.GetBytes(jwt["Key"]!);

// 2) Authentication & Authorization registrieren
builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme    = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
        // ===== Temporär zum Debuggen =====
        options.RequireHttpsMetadata = false;
        options.SaveToken = true;

        options.TokenValidationParameters = new TokenValidationParameters
        {
            // Issuer/Audience validierung testweise deaktiviert
            ValidateIssuer           = false,
            ValidateAudience         = false,
            ValidateLifetime         = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey         = new SymmetricSecurityKey(key),

            // Zum späteren Reaktivieren:
            // ValidIssuer  = jwt["Issuer"],
            // ValidAudience= jwt["Audience"],
        };

        // ← Hier den klassischen JwtSecurityTokenHandler verwenden und Warnung unterdrücken
#pragma warning disable CS0618 // SecurityTokenValidators is obsolete
        options.SecurityTokenValidators.Clear();
        options.SecurityTokenValidators.Add(new JwtSecurityTokenHandler());
#pragma warning restore CS0618

        // ===== Events für Debug-Output =====
        options.Events = new JwtBearerEvents
        {
            OnMessageReceived = ctx =>
            {
                // Raw-Header loggen
                var raw = ctx.Request.Headers["Authorization"].FirstOrDefault();
                Console.WriteLine("▶ Raw Authorization-Header: " + raw);

                // Nur den Token-Teil (nach "Bearer ") extrahieren
                if (!string.IsNullOrEmpty(raw) && raw.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                {
                    ctx.Token = raw["Bearer ".Length..].Trim();
                    Console.WriteLine("▶ Extracted Token: " + ctx.Token);
                }

                return Task.CompletedTask;
            },
            OnAuthenticationFailed = ctx =>
            {
                // Komplette Exception ausgeben
                Console.WriteLine("‼ AuthenticationFailed: " + ctx.Exception);
                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthorization();
builder.Services.AddControllers();

// 3) Swagger so konfigurieren, dass man JWT eingeben kann
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.AddSecurityDefinition("Bearer", new()
    {
        Type         = Microsoft.OpenApi.Models.SecuritySchemeType.Http,
        Scheme       = "bearer",
        BearerFormat = "JWT",
        Description  = "Gib hier dein JWT-Token ein (ohne 'Bearer '):\n\teyJhbGciOiJ..."
    });
    c.AddSecurityRequirement(new()
    {
        {
            new() { Reference = new() { Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme, Id = "Bearer" } },
            Array.Empty<string>()
        }
    });
});

var app = builder.Build();

// Middleware-Pipeline
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseAuthentication(); // zuerst Authentication
app.UseAuthorization();

app.MapControllers();
app.Run();
