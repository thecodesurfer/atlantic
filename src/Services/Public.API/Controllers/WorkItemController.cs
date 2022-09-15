using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;

namespace Atlantic.Services.Public.API.Controllers;

[Authorize("apiPolicy")]
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

public class RequireScopeHandler : AuthorizationHandler<RequireScope>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, RequireScope requirement)
    {
        if (context == null)
            throw new ArgumentNullException(nameof(context));
        if (requirement == null)
            throw new ArgumentNullException(nameof(requirement));

        var scopeClaim = context.User.Claims.FirstOrDefault(t => t.Type == "scope");

        if (scopeClaim != null && (context.User.HasScope("api")))
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}

public class RequireScope : IAuthorizationRequirement { }