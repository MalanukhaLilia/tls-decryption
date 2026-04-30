using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddHttpClient("Casdoor", client =>
{
    client.BaseAddress = new Uri("https://localhost:8443");
}).ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
{
    ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
});

var app = builder.Build();

// 3.a.i
app.MapGet("/login", () =>
{
    var clientId = "7dba2c2496f8e6093795";
    var redirectUri = Uri.EscapeDataString("https://localhost:7266/callback");
    var url = $"https://localhost:8443/login/oauth/authorize?client_id={clientId}&response_type=code&redirect_uri={redirectUri}&scope=openid profile email&state=kpi123";

    return Results.Redirect(url);
});

app.MapGet("/callback", async (string code, HttpContext ctx, IHttpClientFactory httpClientFactory) =>
{
    var client = httpClientFactory.CreateClient("Casdoor");

    var content = new FormUrlEncodedContent(new[]
    {
        new KeyValuePair<string, string>("grant_type", "authorization_code"),
        new KeyValuePair<string, string>("client_id", "7dba2c2496f8e6093795"),
        new KeyValuePair<string, string>("client_secret", "25d55a264c1ae7d141dd8bd826d66b5d6be271be"),
        new KeyValuePair<string, string>("code", code),
        new KeyValuePair<string, string>("redirect_uri", "https://localhost:7266/callback")
    });

    var response = await client.PostAsync("/api/login/oauth/access_token", content);
    var jsonString = await response.Content.ReadAsStringAsync();
    var json = JsonSerializer.Deserialize<JsonElement>(jsonString);

    if (json.TryGetProperty("id_token", out var idTokenElement))
    {
        var idToken = idTokenElement.GetString();
        ctx.Response.Cookies.Append("CasdoorAuth", idToken, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.None
        });
    }

    return Results.Redirect("/");
});

// 3.a.ii
app.MapGet("/user-info", async (HttpContext ctx, IHttpClientFactory httpClientFactory) =>
{
    if (!ctx.Request.Cookies.TryGetValue("CasdoorAuth", out var token))
    {
        return Results.Unauthorized();
    }

    try
    {
        var client = httpClientFactory.CreateClient("Casdoor");

        var jwksJson = await client.GetStringAsync("/api/certs");
        var jwks = new JsonWebKeySet(jwksJson);

        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKeys = jwks.GetSigningKeys(),
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false
        };

        var handler = new JwtSecurityTokenHandler();

        handler.ValidateToken(token, validationParameters, out var validatedToken);

        var jwtToken = (JwtSecurityToken)validatedToken;
        return Results.Ok(jwtToken.Claims.Select(c => new { c.Type, c.Value }));
    }
    catch
    {
        return Results.Unauthorized();
    }
});

// 4
app.MapGet("/logout", (HttpContext ctx) =>
{
    ctx.Response.Cookies.Delete("CasdoorAuth");
    return Results.Redirect("/");
});

app.MapGet("/", (HttpContext ctx) =>
{
    bool isAuthenticated = ctx.Request.Cookies.TryGetValue("CasdoorAuth", out var token);
    string userName = "";

    if (isAuthenticated && !string.IsNullOrEmpty(token))
    {
        try
        {
            var handler = new JwtSecurityTokenHandler();
            var jwt = handler.ReadJwtToken(token);
            userName = jwt.Claims.FirstOrDefault(c => c.Type == "name")?.Value ?? "Студент";
        }
        catch { isAuthenticated = false; }
    }

    string content = $@"
        <!DOCTYPE html>
        <html lang=""uk"">
        <head><meta charset=""UTF-8""><title>OIDC Frontend</title></head>
        <body style=""font-family: sans-serif; padding: 20px;"">
        <h1>Інтеграція з Casdoor OIDC (Raw HTTP)</h1>";

    if (!isAuthenticated)
    {
        content += @"
            <p style=""color: red;"">Ви не увійшли в систему.</p>
            <button onclick=""window.location.href='/login'"" style=""padding: 10px;"">
            Увійти через Casdoor
            </button>";
    }
    else
    {
        content += $@"
            <p style=""color: green;"">Вітаємо, ви успішно авторизовані як: <b>{userName}</b></p>
            <button onclick=""getUserInfo()"" style=""padding: 10px;"">Отримати дані профілю</button>
            <button onclick=""window.location.href='/logout'"" style=""padding: 10px;"">Вийти</button>";
    }

    content += @"
        <pre id=""userInfoDisplay"" style=""background: #f4f4f4; padding: 15px; margin-top: 20px; border-radius: 5px;"">
        Дані з'являться тут після натискання кнопки.
        </pre>
        <script>
            async function getUserInfo() {{
                const response = await fetch('/user-info');
                if (response.ok) {{
                    const data = await response.json();
                    document.getElementById('userInfoDisplay').innerText = JSON.stringify(data, null, 2);
                }} else {{
                    document.getElementById('userInfoDisplay').innerText = 'HTTP ERROR ' + response.status;
                }}
            }}
        </script>
        </body></html>";

    return Results.Content(content, "text/html; charset=utf-8");
});

app.Run();