using Atlantic.Services.Public.API.Controllers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.OpenApi.Models;
using OpenIddict.Validation.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers()
    .AddNewtonsoftJson();

builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;
});

builder.Services.AddOpenIddict()
    .AddValidation(options =>
    {
        options.SetIssuer("https://localhost:9000/");
        options.AddAudiences("rs_atlanticApi");

        options.UseIntrospection()
               .SetClientId("rs_atlanticApi")
               .SetClientSecret("159CF32B-08D9-4424-8924-91B2E6DD2882");

        options.UseSystemNetHttp();

        options.UseAspNetCore();
    });

builder.Services.AddScoped<IAuthorizationHandler, RequireScopeHandler>();

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("apiPolicy", p =>
    {
        p.Requirements.Add(new RequireScope());
    });
});

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "Atlantic API",
        Version = "v1",
    });
});

var app = builder.Build();

app.UseSwagger();
app.UseSwaggerUI(options =>
{
    options.SwaggerEndpoint("/swagger/v1/swagger.json", "Atlantic API V1");
    options.RoutePrefix = string.Empty;
});

app.UseExceptionHandler("/Home/Error");
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.UseEndpoints(endpoints =>
{
    endpoints.MapControllers();
});

app.Run();
