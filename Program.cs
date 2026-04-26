using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

var builder = WebApplication.CreateBuilder(args);

// 1
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
.AddCookie(options => {
    options.Cookie.Name = "CasdoorAuth";
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
})
.AddOpenIdConnect(options =>
{
    options.Authority = "https://localhost:8443";
    options.ClientId = "7dba2c2496f8e6093795";
    options.ClientSecret = "25d55a264c1ae7d141dd8bd826d66b5d6be271be";
    options.ResponseType = "code";
    options.SaveTokens = true;
    options.CallbackPath = "/callback";
    options.RequireHttpsMetadata = false;

    options.BackchannelHttpHandler = new HttpClientHandler
    {
        ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
    };
});

builder.Services.AddAuthorization();

var app = builder.Build();

// 2
app.UseAuthentication();
app.UseAuthorization();

// 3.a.i
app.MapGet("/login", () => Results.Challenge(new AuthenticationProperties { RedirectUri = "/" }));

// 3.a.ii
app.MapGet("/user-info", (HttpContext ctx) =>
{
    if (ctx.User.Identity?.IsAuthenticated == true)
    {
        return Results.Ok(ctx.User.Claims.Select(c => new { c.Type, c.Value }));
    }
    return Results.Unauthorized();
});

// 4
app.MapGet("/", (HttpContext ctx) => {
    bool isAuthenticated = ctx.User.Identity?.IsAuthenticated ?? false;

    string content = $@"
    <!DOCTYPE html>
    <html lang=""uk"">
    <head><meta charset=""UTF-8""><title>OIDC Frontend</title></head>
    <body style=""font-family: sans-serif; padding: 20px;"">
        <h1>Інтеграція з Casdoor OIDC</h1>";

    if (!isAuthenticated)
    {
        {
            content += @"
            <p style=""color: red;"">Ви не увійшли в систему.</p>
            <button onclick=""window.location.href='/login'"" style=""padding: 10px;"">
                Увійти через Casdoor
            </button>";
        }
    }
    else
    {
        {
            content += $@"
            <p style=""color: green;"">Вітаємо, ви успішно авторизовані як: <b>{ctx.User.Identity.Name}</b></p>
            <button onclick=""getUserInfo()"" style=""padding: 10px;"">
                Отримати дані профілю
            </button>
            <button onclick=""window.location.href='/logout'"" style=""padding: 10px;"">Вийти</button>";
        }
    }

    content += @"
        <pre id=""userInfoDisplay"" style=""background: #f4f4f4; padding: 15px; margin-top: 20px; border-radius: 5px;"">
            Дані з'являться тут після натискання кнопки.
        </pre>
        <script>
            async function getUserInfo() {{
                const response = await fetch('/user-info');
                const data = await response.json();
                document.getElementById('userInfoDisplay').innerText = JSON.stringify(data, null, 2);
            }}
        </script>
    </body></html>";

    return Results.Content(content, "text/html; charset=utf-8");
});

app.MapGet("/logout", async (HttpContext ctx) =>
{
    await ctx.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    await ctx.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme);
});

app.Run();