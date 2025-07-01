using Microsoft.AspNetCore.Mvc;

namespace SampleAspireDapr.WebApi.Controllers;

[ApiController]
[Route("[controller]")]
public class HelloController : ControllerBase
{
    [HttpGet]
    public string Get() => "Hello from WebAPI!";
}
