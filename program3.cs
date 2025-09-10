using Blazored.SessionStorage;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Identity.Client;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Validators;
using SINHDemo.Authentication;
using SINHDemo.Components;
using SINHDemo.Models;
using SINHDemo.Services;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
const string MS_OIDC_SCHEME = "MicrosoftOidc";
var builder = WebApplication.CreateBuilder(args);

// Disables endpoint override warning message when using IConfiguration for Kestrel endpoint.
builder.WebHost.UseUrls();

// Add services to the container.
builder.Services.AddAuthentication(MS_OIDC_SCHEME)
    .AddOpenIdConnect(MS_OIDC_SCHEME, oidcOptions =>
    {
        oidcOptions.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        //oidcOptions.Scope.Add(OpenIdConnectScope.OpenIdProfile);
        oidcOptions.CallbackPath = new PathString(builder.Configuration["AzureAd:CallbackPath"]);
        oidcOptions.SignedOutCallbackPath = new PathString(builder.Configuration["AzureAd:SignedOutCallbackPath"]);
        oidcOptions.RemoteSignOutPath = new PathString(builder.Configuration["AzureAd:RemoteSignOutPath"]);
        oidcOptions.Authority = builder.Configuration["AzureAd:Authority"];
        oidcOptions.ClientId = builder.Configuration["AzureAd:ClientId"];
        oidcOptions.ClientSecret = builder.Configuration["AzureAd:ClientSecret"];
        oidcOptions.ResponseType = OpenIdConnectResponseType.Code;
        oidcOptions.MapInboundClaims = false;
        oidcOptions.TokenValidationParameters.NameClaimType = JwtRegisteredClaimNames.Name;
        oidcOptions.TokenValidationParameters.RoleClaimType = "role";
        var microsoftIssuerValidator = AadIssuerValidator.GetAadIssuerValidator(oidcOptions.Authority);
        oidcOptions.TokenValidationParameters.IssuerValidator = microsoftIssuerValidator.Validate;
        oidcOptions.Scope.Add(builder.Configuration["AzureAd:Scopes"]!);
        oidcOptions.Events.OnTokenValidated = context =>
        {
            // Add the access token as a claim so it is available in ClaimsPrincipal
            var accessToken = context.TokenEndpointResponse?.AccessToken;
            if (!string.IsNullOrEmpty(accessToken))
            {
                var identity = context.Principal?.Identity as ClaimsIdentity;

                if (identity != null && !identity.HasClaim(c => c.Type == "access_token"))
                {
                    var azureAdConfig = builder.Configuration.GetSection("AzureAd");
                    var clientId = azureAdConfig["ClientId"];
                    var clientSecret = azureAdConfig["ClientSecret"];
                    var authorityUri = azureAdConfig["Authority"];
                    var accessScopes = new[]
                    {
                        azureAdConfig["GraphApiScopes"],
                        azureAdConfig["AiOperatorScopes"]
                    };

                    var userAssertion = new UserAssertion(accessToken);
                    var confidentialApp = ConfidentialClientApplicationBuilder.Create(clientId)
                        .WithClientSecret(clientSecret)
                        .WithAuthority(authorityUri)
                        .Build();

                    for (int i = 0; i < accessScopes.Length; i++)
                    {
                        var scope = new[] { accessScopes[i] };
                        var tokenResult = confidentialApp.AcquireTokenOnBehalfOf(scope, userAssertion).ExecuteAsync().Result;

                        var claimType = i == 0 ? "graph_api_access_token" : "access_token";
                        identity.AddClaim(new Claim(claimType, tokenResult.AccessToken));
                    }
                }
            }
            return Task.CompletedTask;
        };
        oidcOptions.Events.OnRemoteFailure = context =>
        {
            // This is the way to handle the Signin-oidc Issue it occurs when user gets login / logout error this code can be used
            ArgumentNullException.ThrowIfNull(nameof(context));

            if (context.Failure is not null)
            {
                var failureMessage = context.Failure.Message;

                if (failureMessage.Contains("Correlation failed", StringComparison.InvariantCulture) ||
                    failureMessage.Contains("OpenIdConnectAuthenticationHandler: message.State is null or empty", StringComparison.InvariantCulture) ||
                    failureMessage.Contains("Unable to unprotect the message.State", StringComparison.InvariantCulture))
                {
                    context.Response.Redirect("/");
                    context.HandleResponse();
                }
            }

            return Task.CompletedTask;
        };
    })
    .AddJwtBearer(option =>
    {
        option.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateActor = true,
            RequireAudience = true,
            RequireExpirationTime = true,
            SaveSigninToken = true
        };
    })
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme);

builder.Services.ConfigureCookieOidcRefresh(CookieAuthenticationDefaults.AuthenticationScheme, MS_OIDC_SCHEME);
builder.Services.AddAuthorization();
builder.Services.AddScoped<AuthenticationStateProvider, PersistingAuthenticationStateProvider>();
builder.Services.AddCascadingAuthenticationState();
builder.Services.AddRazorComponents().AddInteractiveServerComponents();
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<AuthService>();
builder.Services.AddScoped<ErrorHandler>();
builder.Services.AddBlazoredSessionStorage();
builder.Services.AddHealthChecks();
builder.Services.AddScoped<SharedData>();
builder.Services.AddBlazorBootstrap();


// Get the configuration details for both Apim and Pulse endpoints
ApimConfig apimConfig = builder.Configuration.GetSection("ApimOption").Get<ApimConfig>()!;
PulseApiConfig pusleConfig = builder.Configuration.GetSection("PulseOptions").Get<PulseApiConfig>()!;
SinhGatewayOptions SinhGatewayConfig = builder.Configuration.GetSection("SinhGatewayOptions").Get<SinhGatewayOptions>()!;

builder.Services.AddSingleton(apimConfig!);
builder.Services.AddSingleton(pusleConfig!);
builder.Services.AddSingleton(SinhGatewayConfig!);

builder.Services.AddTransient<ApiService>();

// Inject both Apim and Pulse httpclient's configuration to the lifecycle
// Apim HttpClient
builder.Services.AddHttpClient("AppApi")
    .ConfigureHttpClient((serviceProvider, client) =>
    {
        var config = serviceProvider.GetRequiredService<ApimConfig>();
        client.BaseAddress = new Uri($"https://{config.Host}");
        client.DefaultRequestHeaders.Add(config.AuthHeaderKey!, config.AuthHeaderValue!);

    });

// Pulse HttpClient
builder.Services.AddHttpClient("PulseApi")
    .ConfigureHttpClient((serviceProvider, client) =>
    {
        var apimConfig = serviceProvider.GetRequiredService<ApimConfig>();
        var config = serviceProvider.GetRequiredService<PulseApiConfig>();
        client.BaseAddress = new Uri(config.Domain);
        client.DefaultRequestHeaders.Add(apimConfig.AuthHeaderKey!, apimConfig.PulseAuthKey!);
    });

// Chat api HttpClient
builder.Services.AddHttpClient("ChatApi")
    .ConfigureHttpClient((serviceProvider, client) =>
    {
        var config = serviceProvider.GetRequiredService<SinhGatewayOptions>();
        client.BaseAddress = new Uri(config.BaseUrl);
    });

// Graph api HttpClient

builder.Services.AddHttpClient("GraphApi")
    .ConfigureHttpClient((serviceProvider, client) =>
    {
        var Baseurl = builder.Configuration["GraphApiOption:BaseUrl"];
        client.BaseAddress = new Uri(Baseurl!);
    });

var app = builder.Build();

app.UseExceptionHandler("/Error", createScopeForErrors: true);
app.UseHsts();

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();
app.MapGroup("/authentication").MapLoginAndLogout();
app.MapHealthChecks("/_health");

app.Run();
