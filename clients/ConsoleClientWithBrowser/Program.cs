using IdentityModel.OidcClient;
using Serilog;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using IdentityModel.OidcClient.Browser;
using IdentityModel.OidcClient.Results;
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

            await Repl(); // Read-eval-print loop.
        }

        private static async Task Repl()
        {
            string currentAccessToken = null;
            string currentRefreshToken = null;
            while (true)
            {
                var menu = "COMMANDS:\n"
                           + (currentAccessToken != null ? "  c : [call api]\n" : "\n")
                           + (currentAccessToken == null ? "  l : [login]\n" : "\n")
                           + (!string.IsNullOrEmpty(currentRefreshToken) ? "  r : [refresh token]\n" : "\n")
                           + (currentRefreshToken != null ? "  s : [steal refresh token]\n" : "\n")
                           + "  x : [exit]\n"
                           + "\n";

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
                        Console.WriteLine("*** CALL API ***\n");
                        await CallApi(currentAccessToken);
                        break;
                    }

                    case ConsoleKey.L:
                    {
                        Console.WriteLine("*** LOGIN ***\n");
                        if (await Login() is LoginResult result)
                        {
                            currentAccessToken = result.AccessToken;
                            currentRefreshToken = result.RefreshToken;

                            _apiClient = new HttpClient(result.RefreshTokenHandler)
                            {
                                BaseAddress = new Uri(_api),
                            };
                        }
                        break;
                    }

                    case ConsoleKey.R:
                    {
                        Console.WriteLine("*** REFRESH TOKEN ***\n");
                        if (await RefreshToken(currentRefreshToken) is RefreshTokenResult refreshResult)
                        {
                            currentAccessToken = refreshResult.AccessToken;
                            currentRefreshToken = refreshResult.RefreshToken;
                        }
                        else
                        {
                            _apiClient!.Dispose();
                            _apiClient = null;

                            currentAccessToken = null;
                            currentRefreshToken = null;
                        }
                        break;
                    }

                    case ConsoleKey.S:
                    {
                        Console.WriteLine("*** STEAL & REFRESH TOKEN ***\n");
                        await StealAndRefreshToken(currentRefreshToken);
                        break;
                    }

                    case ConsoleKey.X:
                    {
                        Console.WriteLine("*** EXIT ***\n");
                        return;
                    }
                }
            }
        }

        private static async Task StealAndRefreshToken(string currentRefreshToken)
        {
            Console.WriteLine($"ATTACKER Stealing Refresh Token:\n  {currentRefreshToken}");

            var refreshResult = await _oidcClient.RefreshTokenAsync(currentRefreshToken);
            if (refreshResult.IsError)
            {
                Console.WriteLine($"Error:\n  {refreshResult.Error}\n");
                return;
            }

            var currentRefreshTokenOfAttacker = refreshResult.RefreshToken;
            var currentAccessTokenOfAttacker = refreshResult.AccessToken;

            Console.WriteLine($"ATTACKER Access Token:\n  {currentAccessTokenOfAttacker}");
            Console.WriteLine();
            Console.WriteLine($"ATTACKER Refresh Token:\n  {currentRefreshTokenOfAttacker}");
        }

        private static async Task CallApi(string currentAccessToken)
        {
            Console.WriteLine($"Using Access Token:\n  {currentAccessToken}\n");

            var response = await _apiClient.GetAsync((string)null);

            if (!response.IsSuccessStatusCode)
            {
                Console.WriteLine($"Error:\n  {response.ReasonPhrase}");
                return;
            }

            var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Console.WriteLine("\n");
            Console.WriteLine(json.RootElement);
        }

        private static async Task<LoginResult> Login()
        {
            var result = await _oidcClient.LoginAsync(new LoginRequest(){ BrowserDisplayMode = DisplayMode.Hidden });
            if (result.IsError)
            {
                Console.WriteLine($"Error:\n  {result.Error}");
                return null;
            }

            Console.WriteLine("Claims:");
            foreach (var claim in result.User.Claims)
            {
                Console.WriteLine($"  {claim.Type}: {claim.Value}");
            }
            Console.WriteLine();

            Console.WriteLine($"Token response:");
            var values = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(result.TokenResponse.Raw)!;
            foreach (var item in values)
            {
                Console.WriteLine($"  {item.Key}: {item.Value}");
            }
            Console.WriteLine();

            return result;
        }

        private static async Task<RefreshTokenResult> RefreshToken(string currentRefreshToken)
        {
            var refreshResult = await _oidcClient.RefreshTokenAsync(currentRefreshToken);
            if (refreshResult.IsError)
            {
                Console.WriteLine($"Error:\n  {refreshResult.Error}\n");
                return null;
            }

            Console.WriteLine($"Access Token:\n  {refreshResult.AccessToken}");
            Console.WriteLine();
            Console.WriteLine($"Refresh Token:\n  {refreshResult.RefreshToken ?? "<none>"}");
            
            return refreshResult;
        }
    }
}
