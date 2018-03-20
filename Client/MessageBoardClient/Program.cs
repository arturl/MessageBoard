using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Identity.Client;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using System.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace MessageBoardConsole
{
    class Program
    {
        const string clientId = "815a718e-1419-4a51-b90d-28ad6bdecac4";
        const string messageBoardBaseAddress = "https://localhost:44324";

        class InputHandler
        {
            public static PublicClientApplication PublicClientApp = new PublicClientApplication(clientId);

            //Set the scope for API call to user.read
            // string[] _scopes = new string[] { "api://815a718e-1419-4a51-b90d-28ad6bdecac4/access_as_user"/*"user.read"*/ };
            string[] _scopes = new string[] { "api://26ad214e-57ce-495b-b9ce-005284263ab6/access_as_user"/*"user.read"*/ };

            public async Task Run()
            {
                AuthenticationResult authResult = null;

                try
                {
                    authResult = await PublicClientApp.AcquireTokenSilentAsync(_scopes, PublicClientApp.Users.FirstOrDefault());
                    //authResult = await PublicClientApp.AcquireTokenAsync(_scopes);
                }
                catch (MsalUiRequiredException ex)
                {
                    // A MsalUiRequiredException happened on AcquireTokenSilentAsync. This indicates you need to call AcquireTokenAsync to acquire a token
                    System.Diagnostics.Debug.WriteLine($"MsalUiRequiredException: {ex.Message}");

                    try
                    {
                        authResult = await PublicClientApp.AcquireTokenAsync(_scopes);
                    }
                    catch (MsalException msalex)
                    {
                        Console.WriteLine($"Error Acquiring Token:{System.Environment.NewLine}{msalex}");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error Acquiring Token Silently:{System.Environment.NewLine}{ex}");
                    return;
                }

                if (authResult == null)
                {
                    Console.WriteLine($"Authentication failed, exiting");
                    return;
                }

                var parsedToken = new JwtSecurityToken(authResult.AccessToken);
                var user = parsedToken.Claims.FirstOrDefault(c => c.Type == "preferred_username")?.Value;

                while (true)
                {
                    Console.Write($"{user}>");
                    var command = Console.ReadLine();
                    var words = command.Split(' ', '\t');
                    if (words.Count() < 1)
                        continue;
                    switch (words[0])
                    {
                    case "get":
                    {
                        // Get my messages
                        var messages = await GetHttpContentWithToken(messageBoardBaseAddress + "/api/messageboard", authResult.AccessToken);
                        Console.WriteLine(JsonConvert.DeserializeObject(messages));
                        break;
                    }
                    case "send":
                    {
                        // Send 
                        if (words.Count() < 3)
                        {
                            Console.WriteLine($"Syntax: 'to recipient@email.com Message");
                        }
                        var recipient = words[1];
                        var messageText = words.Skip(2).Aggregate((w1, w2) => $"{w1} {w2}");

                        var message = new { Sender = user, Recipient = recipient, Text = messageText };

                        var content = new StringContent(JsonConvert.SerializeObject(message));
                        var response = await PostHttpContentWithToken(messageBoardBaseAddress + "/api/messageboard", authResult.AccessToken, content);
                        Console.WriteLine(response);

                        break;
                    }
                    default:
                        Console.WriteLine($"Allowed commands are:");
                        Console.WriteLine($"get                              - check your messages");
                        Console.WriteLine($"send <recipient-email> <message> - send message to recipient");
                        Console.WriteLine($"exit                             - exit program");
                        break;
                    }
                }
            }

            public static Task<string> GetHttpContentWithToken(string url, string token)
            {
                return ProcessHttpRequestWithToken(token, (httpClient) => httpClient.GetAsync(url));
            }

            public static Task<string> PostHttpContentWithToken(string url, string token, HttpContent content)
            {
                return ProcessHttpRequestWithToken(token, 
                    (httpClient) =>
                    {
                        return httpClient.PostAsync(url, content);
                    });
            }

            internal static async Task<string> ProcessHttpRequestWithToken(string token, Func<HttpClient, Task<HttpResponseMessage>> makeResponse)
            {
                var httpClient = new HttpClient();
                httpClient.Timeout = TimeSpan.FromMinutes(60);

                httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
                HttpResponseMessage response = await makeResponse(httpClient);

                string textResponse = "?";
                if (response.IsSuccessStatusCode)
                {
                    textResponse = await response.Content.ReadAsStringAsync();
                }
                else
                {
                    if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized)
                    {
                        // If the To Do list service returns access denied, clear the token cache and have the user sign-in again.
                        Console.WriteLine("Sorry, you don't have access to the To Do Service.  Please sign-in again.");
                    }
                    else
                    {
                        Console.WriteLine("Sorry, an error occurred accessing your To Do list.  Please try again.");
                    }
                }

                return textResponse;
            }
        }

        static async Task Test()
        {
            var message = new { Sender = "aa", Recipient = "rr", Text = "aaa"};
            var content = new StringContent(JsonConvert.SerializeObject(message));
            var resp = await InputHandler.PostHttpContentWithToken("http://localhost:58343/api/bot", "blah-token", content);

        }

        static void Main(string[] args)
        {
            JsonConvert.DefaultSettings = () => new JsonSerializerSettings()
            {
                ContractResolver = new CamelCasePropertyNamesContractResolver(),
                Formatting = Formatting.Indented,
                NullValueHandling = NullValueHandling.Ignore,
            };

            new InputHandler().Run().Wait();
            //Test().Wait();
        }
    }
}
