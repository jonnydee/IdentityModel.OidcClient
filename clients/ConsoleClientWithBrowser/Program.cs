using IdentityModel.OidcClient;
using Serilog;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using Serilog.Sinks.SystemConsole.Themes;

namespace ConsoleClientWithBrowser
{
    public class Program
    {
        static string _authority = "https://demo.duendesoftware.com";
        static string _api = "https://demo.duendesoftware.com/api/test";

        static OidcClient _oidcClient;
        static HttpClient _apiClient = new HttpClient { BaseAddress = new Uri(_api) };

        public static async Task Main()
        {
            Console.WriteLine("+-----------------------+");
            Console.WriteLine("|  Sign in with OIDC    |");
            Console.WriteLine("+-----------------------+");
            Console.WriteLine("");
            Console.WriteLine("Press any key to sign in...");
            Console.ReadKey();

            await SignIn();
        }

        private static async Task SignIn()
        {
            // create a redirect URI using an available port on the loopback address.
            // requires the OP to allow random ports on 127.0.0.1 - otherwise set a static port
            var browser = new SystemBrowser();
            var redirectUri = $"http://127.0.0.1:{browser.Port}";

            var options = new OidcClientOptions
            {
                Authority = _authority,
                ClientId = "interactive.public",
                RedirectUri = redirectUri,
                Scope = "openid profile api offline_access",
                FilterClaims = false,

                Browser = browser,
                IdentityTokenValidator = new JwtHandlerIdentityTokenValidator(),
                RefreshTokenInnerHttpHandler = new SocketsHttpHandler(),
            };

            var serilog = new LoggerConfiguration()
                .MinimumLevel.Debug()
                .Enrich.FromLogContext()
                .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level}] {SourceContext}{NewLine}{Message}{NewLine}{Exception}{NewLine}", theme: AnsiConsoleTheme.Code)
                .CreateLogger();

            options.LoggerFactory.AddSerilog(serilog);

            _oidcClient = new OidcClient(options);
            var result = await _oidcClient.LoginAsync(new LoginRequest());

            _apiClient = new HttpClient(result.RefreshTokenHandler)
            {
                BaseAddress = new Uri(_api)
            };

            ShowResult(result);
            await NextSteps(result);
        }

        private static void ShowResult(LoginResult result)
        {
            if (result.IsError)
            {
                Console.WriteLine($"Error:\n  {result.Error}");
                return;
            }

            Console.WriteLine("Claims:");
            foreach (var claim in result.User.Claims)
            {
                Console.WriteLine($"  {claim.Type}: {claim.Value}");
            }
            Console.WriteLine();

            Console.WriteLine($"Token response:");
            var values = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(result.TokenResponse.Raw);
            foreach (var item in values)
            {
                Console.WriteLine($"  {item.Key}: {item.Value}");
            }
            Console.WriteLine();
        }

        private static async Task NextSteps(LoginResult result)
        {
            var currentAccessToken = result.AccessToken;
            var currentRefreshToken = result.RefreshToken;

            var menu = "COMMANDS:\n"
                + "  x : [exit]\n"
                + "  c : [call api]\n"
                + (!string.IsNullOrEmpty(currentRefreshToken) ? "  r : [refresh token]\n" : "\n")
                + "\n";
            
            while (true)
            {
                Console.WriteLine();
                Console.WriteLine("--------------------------------------------");
                Console.Write(menu);
                Console.Write("?> ");
                var key = Console.ReadKey();
                Console.WriteLine();

                switch (key.Key)
                {
                    case ConsoleKey.C:
                    {
                        await CallApi();
                        break;
                    }

                    case ConsoleKey.R:
                    {
                        var refreshResult = await _oidcClient.RefreshTokenAsync(currentRefreshToken);
                        if (refreshResult.IsError)
                        {
                            Console.WriteLine($"Error:\n  {refreshResult.Error}\n");
                        }
                        else
                        {
                            currentRefreshToken = refreshResult.RefreshToken;
                            currentAccessToken = refreshResult.AccessToken;

                            Console.WriteLine($"Access Token:\n  {currentAccessToken}");
                            Console.WriteLine();
                            Console.WriteLine($"Refresh Token:\n  {currentRefreshToken ?? "<none>"}");
                        }
                        break;
                    }

                    case ConsoleKey.X: return;
                }
            }
        }

        private static async Task CallApi()
        {
            var response = await _apiClient.GetAsync("");

            if (response.IsSuccessStatusCode)
            {
                var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
                Console.WriteLine("\n");
                Console.WriteLine(json.RootElement);
            }
            else
            {
                Console.WriteLine($"Error:\n  {response.ReasonPhrase}");
            }
        }
    }
}