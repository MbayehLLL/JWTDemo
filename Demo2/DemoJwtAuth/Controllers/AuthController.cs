using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IConfiguration _cfg;
    public AuthController(IConfiguration cfg) => _cfg = cfg;

    // POST api/auth/login
    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginModel creds)
    {
        // **Demo**: Harte Prüfung, nur user/pass = demo/demo zulässig
        if (creds.User != "demo" || creds.Pass != "demo")
            return Unauthorized("Ungültige Anmeldedaten");

        var jwt = _cfg.GetSection("JwtSettings");
        var key = Encoding.UTF8.GetBytes(jwt["Key"]!);

        var token = new JwtSecurityToken(
            issuer: jwt["Issuer"],
            audience: jwt["Audience"],
            claims: new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, creds.User),
                new Claim("role", "DemoUser")
            },
            expires: DateTime.UtcNow.AddMinutes(30),
            signingCredentials: new SigningCredentials(
                new SymmetricSecurityKey(key),
                SecurityAlgorithms.HmacSha256
            )
        );

        return Ok(new
        {
            token = new JwtSecurityTokenHandler().WriteToken(token),
            expires = token.ValidTo
        });
    }
}

public record LoginModel(string User, string Pass);
