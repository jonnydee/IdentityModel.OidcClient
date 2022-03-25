using IdentityModel.OidcClient;
using Serilog;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using IdentityModel.Client;
using IdentityModel.OidcClient.Browser;
using IdentityModel.OidcClient.Results;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Serilog.Sinks.SystemConsole.Themes;

namespace ConsoleClientWithBrowser
{
    internal class User
    {
        public User(string name)
        {
            this.Name = name;
        }

        public string Name { get; init; }
        public OidcClient OidcClient { get; init; }
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
        public HttpClient ApiClient { get; set; }
        public string TokenEndpoint { get; set; }
        public string UserInfoEndpoint { get; set; }
    }

    public class Program
    {
        static string _authority = "https://demo.duendesoftware.com";
        static string _api = "https://demo.duendesoftware.com/api/test";

        private static User User;
        private static User Attacker;

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

            User = new User(nameof(User).ToUpper())
            {
                OidcClient = new OidcClient(options),
            };

            Attacker = new User(nameof(Attacker).ToUpper());

            await Repl(); // Read-eval-print loop.
        }

        private static async Task Repl()
        {
            LoginResult login = null;
            string currentAccessToken = null;
            string currentRefreshToken = null;
            string currentRefreshTokenOfAttacker = null;
            string currentAccessTokenOfAttacker = null;

            while (true)
            {
                var menu = "\n"
                           + "============================================\n"
                           + "= COMMANDS\n"
                           + "============================================\n\n"
                           + "  x : [exit]\n"
                           + "\nUSER\n\n"
                           + (login == null ? "  a : [login]\n" : "")
                           + (User.AccessToken != null ? "  b : [call api]\n" : "")
                           + (User.RefreshToken != null ? "  c : [refresh token]\n" : "")
                           + (User.AccessToken != null ? "  d : [get user info]\n" : "")
                           + "\nATTACKER\n\n"
                           + (User.RefreshToken != null ? "  k : [steal refresh token]\n" : "")
                           + (Attacker.AccessToken != null ? "  l : [call api]\n" : "")
                           + (Attacker.RefreshToken != null ? "  m : [refresh token]\n" : "")
                           + (Attacker.AccessToken != null ? "  n : [get user info]\n" : "")
                           + "\n";

                Console.Write(menu);
                Console.Write("?> ");
                var key = Console.ReadKey();
                Console.WriteLine();

                switch (key.Key)
                {
                    case ConsoleKey.A:
                    {
                        login = await Login(User);
                        break;
                    }

                    case ConsoleKey.B:
                    {
                        await CallApi(User);
                        break;
                    }

                    case ConsoleKey.C:
                    {
                        if (await RefreshToken(User) is null)
                        {
                            login = null;
                        }
                        break;
                    }

                    case ConsoleKey.D:
                    {
                        await GetUserInfo(User);
                        break;
                    }

                    case ConsoleKey.K:
                    {
                        await AttackerStealToken(Attacker, User);
                        break;
                    }

                    case ConsoleKey.L:
                    {
                        await CallApi(Attacker);
                        break;
                    }

                    case ConsoleKey.M:
                    {
                        await AttackerRefreshToken(Attacker);
                        break;
                    }

                    case ConsoleKey.N:
                    {
                        await AttackerGetUserInfo(Attacker);
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

        private static async Task<UserInfoResult> GetUserInfo(User user)
        {
            Console.WriteLine($"*** {user.Name}: [get user info] ***\n");

            var result = await user.OidcClient.GetUserInfoAsync(user.AccessToken);

            if (result.IsError)
            {
                Console.WriteLine($"Error:\n  {result.Error}");
                return null;
            }

            Console.WriteLine("Claims:");
            foreach (var claim in result.Claims)
            {
                Console.WriteLine($"  {claim.Type}: {claim.Value}");
            }
            Console.WriteLine();

            return result;

        }

        private static async Task<UserInfoResponse> AttackerGetUserInfo(User attacker)
        {
            Console.WriteLine($"*** {attacker.Name}: [get user info] ***\n");

            var result = await attacker.ApiClient.GetUserInfoAsync(new UserInfoRequest
            {
                Address = attacker.UserInfoEndpoint,
                ClientId = "interactive.public",
                ClientAssertion = new ClientAssertion(),
                ClientCredentialStyle = ClientCredentialStyle.PostBody,
                Token = attacker.AccessToken,
            });

            if (result.IsError)
            {
                Console.WriteLine($"Error:\n  {result.Error}");
                return null;
            }

            Console.WriteLine("Claims:");
            foreach (var claim in result.Claims)
            {
                Console.WriteLine($"  {claim.Type}: {claim.Value}");
            }
            Console.WriteLine();

            return result;
        }

        private static async Task AttackerStealToken(User attacker, User user)
        {
            Console.WriteLine($"*** {attacker.Name}: [steal token] from {user.Name} ***\n");

            var client = new HttpClient
            {
                BaseAddress = new Uri(_api),
            };

            // Lookup token endpoint.
            string tokenEndpoint, userInfoEndpoint;
            {
                var response = await client.GetDiscoveryDocumentAsync(new DiscoveryDocumentRequest
                {
                    Address = _authority,
                    Policy = new DiscoveryPolicy(),
                }, CancellationToken.None);
                if (response.IsError)
                {
                    Console.WriteLine($"Error:\n  {response.Error}");
                    return;
                }
                tokenEndpoint = response.TokenEndpoint;
                userInfoEndpoint = response.UserInfoEndpoint;
            }

            attacker.ApiClient = client;
            attacker.TokenEndpoint = tokenEndpoint;
            attacker.UserInfoEndpoint = userInfoEndpoint;
            attacker.AccessToken = user.AccessToken;
            attacker.RefreshToken = user.RefreshToken;

            Console.WriteLine($"{attacker.Name} stole Access Token:\n  {attacker.AccessToken}");
            Console.WriteLine();
            Console.WriteLine($"{attacker.Name} stole Refresh Token:\n  {attacker.RefreshToken}");
        }

        private static async Task AttackerRefreshToken(User attacker)
        {
            Console.WriteLine($"*** {attacker.Name}: [refresh token] ***\n");

            var response = await attacker.ApiClient.RequestRefreshTokenAsync(new RefreshTokenRequest
            {
                Address = attacker.TokenEndpoint,
                ClientId = "interactive.public",
                ClientAssertion = new ClientAssertion(),
                ClientCredentialStyle = ClientCredentialStyle.PostBody,
                RefreshToken = attacker.RefreshToken,
            }, CancellationToken.None);

            if (response.IsError)
            {
                Console.WriteLine($"Error:\n  {response.Error}");
                return;
            }

            attacker.AccessToken = response.AccessToken;
            attacker.RefreshToken = response.RefreshToken;

            Console.WriteLine($"{attacker.Name} Access Token:\n  {attacker.AccessToken}");
            Console.WriteLine();
            Console.WriteLine($"{attacker.Name} Refresh Token:\n  {attacker.RefreshToken}");
        }

        private static async Task CallApi(User user)
        {
            Console.WriteLine($"*** {user.Name}: [call api] ***\n");
            Console.WriteLine($"Using Access Token for API call:\n  {user.AccessToken}\n");

            var response = await user.ApiClient.GetAsync((string)null);

            if (!response.IsSuccessStatusCode)
            {
                Console.WriteLine($"Error:\n  {response.ReasonPhrase}");
                return;
            }

            var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Console.WriteLine("\n");
            Console.WriteLine(json.RootElement);
        }

        private static async Task<LoginResult> Login(User user)
        {
            Console.WriteLine($"*** {user.Name}: [login] ***\n");

            var result = await user.OidcClient.LoginAsync(new LoginRequest());
            if (result.IsError)
            {
                Console.WriteLine($"Error:\n  {result.Error}");
                return null;
            }

            user.AccessToken = result.AccessToken;
            user.RefreshToken = result.RefreshToken;
            user.ApiClient = new HttpClient(result.RefreshTokenHandler)
            {
                BaseAddress = new Uri(_api),
            };

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

        private static async Task<RefreshTokenResult> RefreshToken(User user)
        {
            Console.WriteLine($"*** {user.Name}: [refresh token] ***\n");

            var result = await user.OidcClient.RefreshTokenAsync(user.RefreshToken);
            if (result.IsError)
            {
                Console.WriteLine($"Error:\n  {result.Error}\n");
                return null;
            }

            user.AccessToken = result.AccessToken;
            user.RefreshToken = result.RefreshToken;

            Console.WriteLine($"{user.Name} Access Token:\n  {user.AccessToken}");
            Console.WriteLine();
            Console.WriteLine($"{user.Name} Refresh Token:\n  {user.RefreshToken ?? "<none>"}");
            
            return result;
        }
    }
}
