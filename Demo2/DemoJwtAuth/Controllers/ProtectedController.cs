using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("api/[controller]")]
public class ProtectedController : ControllerBase
{
    // GET api/protected
    [HttpGet]
    [Authorize]
    public IActionResult GetSecret()
        => Ok(new { Message = "🎉 Du hast den geschützten Endpunkt erreicht!" });
}
