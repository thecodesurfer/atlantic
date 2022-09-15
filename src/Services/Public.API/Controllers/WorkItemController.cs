using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Atlantic.Services.Public.API.Controllers;

[Authorize]
[ApiController]
[Route("api/workitems")]
public class WorkItemController : Controller
{
    [HttpGet]
    public IActionResult GetWorkItems()
    {
        return Ok();
    }
}