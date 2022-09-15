using Atlantic.Services.Public.API.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Atlantic.Services.Public.API.Controllers;

[Authorize]
[ApiController]
[ApiVersion("1.0")]
[Route("api/v{version:apiVersion}/workitem-states")]
public class WorkItemStateController : ControllerBase
{
    [HttpGet]
    [ProducesResponseType(StatusCodes.Status200OK, Type = typeof(List<WorkItemType>))]
    public IActionResult GetWorkItemStates()
    {
        throw new NotImplementedException();
    }
}