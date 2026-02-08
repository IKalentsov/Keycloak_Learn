using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

var keycloakAuthority = builder.Configuration["Keycloak:Authority"]!;
var keycloakClientId = builder.Configuration["Keycloak:ClientId"]!;

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.MetadataAddress = builder.Configuration["Keycloak:MetadataAddress"]!;
        options.Audience = builder.Configuration["Keycloak:Audience"];

        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidIssuer = builder.Configuration["Keycloak:Issuer"]
        };

        options.RequireHttpsMetadata = !builder.Environment.IsDevelopment();
    });

builder.Services.AddAuthorization();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo { Title = "Keycloak Demo", Version = "v1", });

    options.AddSecurityDefinition(nameof(SecuritySchemeType.OAuth2),
        new OpenApiSecurityScheme
        {
            Type = SecuritySchemeType.OAuth2,
            Flows = new OpenApiOAuthFlows
            {
                AuthorizationCode = new OpenApiOAuthFlow
                {
                    AuthorizationUrl = new Uri($"{keycloakAuthority}/protocol/openid-connect/auth"),
                    TokenUrl = new Uri($"{keycloakAuthority}/protocol/openid-connect/token"),
                    Scopes = new Dictionary<string, string>
                    {
                        { "openid", "OpenID Connect scope" },
                        { "profile", "User profile" }
                    }
                }
            }
        });

    options.AddSecurityRequirement(doc => new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecuritySchemeReference(nameof(SecuritySchemeType.OAuth2), doc),
            []
        }
    });
});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(options =>
    {
        options.OAuthClientId(keycloakClientId); // Default Client ID
        options.OAuthUsePkce(); // Proof Key for Code Exchange (security enhancement)
    });
}

app.UseHttpsRedirection();

app.UseAuthentication();

app.UseAuthorization();

app.MapGet("users/me", (ClaimsPrincipal user) =>
    {
        return Results.Ok(new
        {
            UserId = user.FindFirstValue(ClaimTypes.NameIdentifier),
            Email = user.FindFirstValue(ClaimTypes.Email),
            Name = user.FindFirstValue("preferred_username"),
            Claims = user.Claims.Select(c => new { c.Type, c.Value })
        });
    })
    .RequireAuthorization();

await app.RunAsync();
