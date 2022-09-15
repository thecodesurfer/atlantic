using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.SwaggerGen;

namespace Atlantic.Services.Public.API.Controllers;

[Authorize]
[ApiController]
[ApiVersion("1.0")]
[Route("api/v{version:apiVersion}/workitems")]
public class WorkItemController : ControllerBase
{
    [HttpGet]
    public IActionResult GetWorkItems()
    {
        return Ok();
    }
}

[Authorize]
[ApiController]
[ApiVersion("1.0")]
[Route("api/v{version:apiVersion}/workitem-types")]
public class WorkItemTypeController : ControllerBase
{

}