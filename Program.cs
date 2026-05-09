using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using ProtoBuf;
using System.Collections.Concurrent;
using System.Net.WebSockets;
using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;
using System.Net.Http.Headers;
using System.Security.Cryptography.X509Certificates;
using System.Security.Authentication;
using System.Net.Security;

var builder = WebApplication.CreateBuilder(args);

builder.WebHost.ConfigureKestrel(serverOptions =>
{
    serverOptions.ListenAnyIP(7266, listenOptions =>
    {
        listenOptions.Protocols = HttpProtocols.Http1;
        var cert = X509Certificate2.CreateFromPemFile("cert.pem", "key.pem");
        if (OperatingSystem.IsWindows())
        {
            cert = new X509Certificate2(cert.Export(X509ContentType.Pfx));
        }
        listenOptions.UseHttps(new TlsHandshakeCallbackOptions
        {
            OnConnection = context =>
            {
                var authOptions = new SslServerAuthenticationOptions
                {
                    ServerCertificate = cert,
                    EnabledSslProtocols = SslProtocols.Tls12
                };

                authOptions.CipherSuitesPolicy = new CipherSuitesPolicy(new[]
                {
                    TlsCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256,
                    TlsCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
                    TlsCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256,
                    TlsCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA
                });

                return new ValueTask<SslServerAuthenticationOptions>(authOptions);
            }
        });
    });
});

var casdoorUrl = builder.Configuration["CASDOOR_URL"] ?? "https://localhost:8443";

builder.Services.AddHttpClient("Casdoor", client =>
{
    client.BaseAddress = new Uri(casdoorUrl);
}).ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
{
    ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
});

var allSymbols = new[] { "BTCUSDT", "ETHUSDT", "BNBUSDT", "ADAUSDT", "SOLUSDT", "DOTUSDT", "DOGEUSDT", "XRPUSDT", "LTCUSDT", "LINKUSDT", "MATICUSDT", "SHIBUSDT", "AVAXUSDT", "UNIUSDT" };
var randomSymbols = allSymbols.OrderBy(x => Guid.NewGuid()).Take(5).ToList();
var binanceStreamUrl = $"wss://stream.binance.com:9443/ws/{string.Join("/", randomSymbols.Select(s => $"{s.ToLower()}@ticker"))}";

var connections = new ConcurrentDictionary<WebSocket, List<string>>();

_ = Task.Run(async () => {
    while (true)
    {
        try
        {
            using var binanceWs = new ClientWebSocket();
            await binanceWs.ConnectAsync(new Uri(binanceStreamUrl), CancellationToken.None);
            var buffer = new byte[4096];
            while (binanceWs.State == WebSocketState.Open)
            {
                var result = await binanceWs.ReceiveAsync(new ArraySegment<byte>(buffer), CancellationToken.None);
                if (result.MessageType == WebSocketMessageType.Close) break;

                var jsonString = System.Text.Encoding.UTF8.GetString(buffer, 0, result.Count);
                using var doc = JsonDocument.Parse(jsonString);
                var root = doc.RootElement;

                if (root.TryGetProperty("s", out var symbolEl) && root.TryGetProperty("c", out var priceEl))
                {
                    var update = new CryptoUpdate 
                    { 
                        Symbol = symbolEl.GetString() ?? "", 
                        Price = priceEl.GetString() ?? "0.00",
                        Timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
                    };
                    
                    using var ms = new MemoryStream();
                    Serializer.Serialize(ms, update);
                    var bytes = ms.ToArray();

                    foreach (var kvp in connections)
                    {
                        if (kvp.Value.Contains(update.Symbol))
                        {
                            if (kvp.Key.State == WebSocketState.Open)
                            {
                                try { await kvp.Key.SendAsync(new ArraySegment<byte>(bytes), WebSocketMessageType.Binary, true, CancellationToken.None); }
                                catch { }
                            }
                        }
                    }
                }
            }
        }
        catch (Exception) 
        { 
            await Task.Delay(5000); 
        }
    }
});

var app = builder.Build();

app.UseWebSockets();

async Task<TokenValidationParameters> GetValidationParams(IHttpClientFactory factory)
{
    var client = factory.CreateClient("Casdoor");
    var clientId = "7dba2c2496f8e6093795";
    var clientSecret = "25d55a264c1ae7d141dd8bd826d66b5d6be271be";
    var keys = new List<SecurityKey>();

    try
    {
        var jwksJson = await client.GetStringAsync($"/api/certs?clientId={clientId}&clientSecret={clientSecret}");
        if (!jwksJson.Contains("\"status\": \"error\""))
        {
            var jwks = new JsonWebKeySet(jwksJson);
            keys = jwks.GetSigningKeys().ToList();
        }
    }
    catch { }

    var validationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = keys.Any(),
        IssuerSigningKeys = keys,
        IssuerSigningKey = keys.FirstOrDefault(),
        ValidateIssuer = false,
        ValidateAudience = false,
        ValidateLifetime = false
    };

    if (!keys.Any())
    {
        validationParameters.SignatureValidator = delegate (string token, TokenValidationParameters parameters)
        {
            return new JwtSecurityToken(token);
        };
    }

    return validationParameters;
}

app.Map("/ws", async (HttpContext ctx, IHttpClientFactory httpClientFactory) =>
{
    if (!ctx.WebSockets.IsWebSocketRequest) { ctx.Response.StatusCode = 400; return; }

    if (!ctx.Request.Cookies.TryGetValue("CasdoorAuth", out var token)) { ctx.Response.StatusCode = 401; return; }

    try
    {
        var validationParameters = await GetValidationParams(httpClientFactory);
        new JwtSecurityTokenHandler().ValidateToken(token, validationParameters, out _);
    }
    catch { ctx.Response.StatusCode = 401; return; }

    using var webSocket = await ctx.WebSockets.AcceptWebSocketAsync();
    connections.TryAdd(webSocket, new List<string>());

    var buffer = new byte[1024];
    while (webSocket.State == WebSocketState.Open)
    {
        var result = await webSocket.ReceiveAsync(new ArraySegment<byte>(buffer), CancellationToken.None);
        if (result.MessageType == WebSocketMessageType.Close) break;

        try
        {
            using var ms = new MemoryStream(buffer, 0, result.Count);
            var req = Serializer.Deserialize<WsRequest>(ms);
            if (req.Action == "SUBSCRIBE" && !string.IsNullOrEmpty(req.Symbol))
            {
                connections[webSocket] = new List<string> { req.Symbol };
            }
        }
        catch { }
    }
    connections.TryRemove(webSocket, out _);
});

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

app.MapGet("/user-info", async (HttpContext ctx, IHttpClientFactory httpClientFactory) =>
{
    if (!ctx.Request.Cookies.TryGetValue("CasdoorAuth", out var token)) return Results.Text("Кука CasdoorAuth відсутня.", statusCode: 401);

    try
    {
        var validationParameters = await GetValidationParams(httpClientFactory);
        var handler = new JwtSecurityTokenHandler();
        handler.ValidateToken(token, validationParameters, out var validatedToken);
        var jwtToken = (JwtSecurityToken)validatedToken;
        return Results.Ok(jwtToken.Claims.Select(c => new { c.Type, c.Value }));
    }
    catch (Exception ex)
    {
        return Results.Text($"Деталі помилки: {ex.Message}", statusCode: 401);
    }
});

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

    string symbolButtons = string.Join(" ", randomSymbols.Select(s => 
        $@"<button onclick=""subscribe('{s}')"">{s}</button>"));

    string content = $@"
<!DOCTYPE html>
<html lang=""uk"">
<head>
    <meta charset=""UTF-8"">
    <title>Crypto WS Lab</title>
    <style>
        body {{ font-family: sans-serif; padding: 20px; }}
        .card {{ border: 1px solid #ccc; padding: 15px; margin: 10px 0; }}
        #wsData {{ font-size: 2em; font-weight: bold; }}
        #userInfoDisplay {{ background: #eee; padding: 10px; display: none; }}
        .price-up {{ color: green; }}
        .price-down {{ color: red; }}
    </style>
</head>
<body>
    <h1>WebSocket Crypto Lab</h1>";

    if (!isAuthenticated)
    {{
        content += $@"
        <div>
            <p>Ви не авторизовані.</p>
            <button onclick=""window.location.href='/login'"">Увійти через Casdoor</button>
        </div>";
    }}
    else
    {{
        content += $@"
        <div class=""card"">
            <p>Вітаємо, <b>{userName}</b></p>
            <button onclick=""toggleUserInfo()"">Показати дані профілю</button>
            <button onclick=""window.location.href='/logout'"">Вийти</button>
            <pre id=""userInfoDisplay""></pre>
        </div>

        <div class=""card"">
            <h3>Виберіть монету:</h3>
            {symbolButtons}
        </div>

        <div class=""card"">
            <div id=""activeSymbol"">Виберіть актив</div>
            <div id=""wsData"">---</div>
            <small id=""wsStatus"">Очікування підключення...</small>
        </div>";
    }}

    content += @"
    <script src=""https://cdn.jsdelivr.net/npm/protobufjs@7.2.4/dist/protobuf.min.js""></script>
    <script>
        let ws;
        let currentPrice = 0;
        const root = protobuf.Root.fromJSON({
            nested: {
                CryptoUpdate: {
                    fields: {
                        Symbol: { type: 'string', id: 1 },
                        Price: { type: 'string', id: 2 },
                        Timestamp: { type: 'int64', id: 3 }
                    }
                },
                WsRequest: {
                    fields: {
                        Action: { type: 'string', id: 1 },
                        Symbol: { type: 'string', id: 2 }
                    }
                }
            }
        });
        const CryptoUpdate = root.lookupType('CryptoUpdate');
        const WsRequest = root.lookupType('WsRequest');

        function toggleUserInfo() {
            const el = document.getElementById('userInfoDisplay');
            if (el.style.display === 'block') {
                el.style.display = 'none';
            } else {
                getUserInfo();
            }
        }

        async function getUserInfo() {
            const el = document.getElementById('userInfoDisplay');
            el.style.display = 'block';
            el.innerText = 'Завантаження...';
            const response = await fetch('/user-info');
            if (response.ok) {
                const data = await response.json();
                el.innerText = JSON.stringify(data, null, 2);
            } else {
                el.innerText = 'Помилка завантаження';
            }
        }

        function subscribe(symbol) {
            document.getElementById('activeSymbol').innerText = 'Актив: ' + symbol;
            
            const sendSub = () => {
                const msg = WsRequest.create({ Action: 'SUBSCRIBE', Symbol: symbol });
                const buffer = WsRequest.encode(msg).finish();
                ws.send(buffer);
            };

            if (!ws || ws.readyState !== WebSocket.OPEN) {
                const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
                ws = new WebSocket(`${wsProtocol}//${window.location.host}/ws`);
                ws.binaryType = 'arraybuffer';
                
                ws.onopen = () => {
                    document.getElementById('wsStatus').innerText = 'З’єднано';
                    sendSub();
                };
                
                ws.onmessage = (e) => {
                    const msg = CryptoUpdate.decode(new Uint8Array(e.data));
                    const price = parseFloat(msg.Price);
                    const el = document.getElementById('wsData');
                    
                    if (price > currentPrice) el.className = 'price-up';
                    else if (price < currentPrice) el.className = 'price-down';
                    
                    el.innerText = '$' + price.toFixed(2);
                    currentPrice = price;
                };

                ws.onclose = () => {
                    document.getElementById('wsStatus').innerText = 'Роз’єднано';
                };
            } else {
                sendSub();
            }
        }
    </script>
</body>
</html>";

    return Results.Content(content, "text/html; charset=utf-8");
});

app.Run();

[ProtoContract]
public class CryptoUpdate
{
    [ProtoMember(1)]
    public string Symbol { get; set; } = string.Empty;

    [ProtoMember(2)]
    public string Price { get; set; } = string.Empty;

    [ProtoMember(3)]
    public long Timestamp { get; set; }
}

[ProtoContract]
public class WsRequest
{
    [ProtoMember(1)]
    public string Action { get; set; } = string.Empty;

    [ProtoMember(2)]
    public string Symbol { get; set; } = string.Empty;
}