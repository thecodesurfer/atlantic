using Atlantic.Services.Public.API.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Atlantic.Services.Public.API.Controllers;

[Authorize]
[ApiController]
[ApiVersion("1.0")]
[Route("api/v{version:apiVersion}/workitems")]
public class WorkItemController : ControllerBase
{
    [HttpGet]
    [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(List<WorkItem>))]
    public IActionResult GetWorkItems()
    {
        throw new NotImplementedException();
    }
}
