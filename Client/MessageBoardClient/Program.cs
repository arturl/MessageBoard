using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Identity.Client;
// using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace TodoListClientConsole
{
    class Program
    {
        //const string tenant = "microsoft.onmicrosoft.com";
        const string clientId = "815a718e-1419-4a51-b90d-28ad6bdecac4"; //"fd952aef-2735-4100-b074-438c2a4914d5";
        //const string aadInstance = "https://login.microsoftonline.com/{0}";

        //static string authority = "https://login.windows.net/common/oauth2/authorize";  // String.Format(aadInstance, tenant);

        //const string todoListResourceId = "https://contoso.onmicrosoft.com/TodoListService";
        const string todoListBaseAddress = "https://localhost:44324";

        class Test
        {
            public static PublicClientApplication PublicClientApp = new PublicClientApplication(clientId);

            //Set the API Endpoint to Graph 'me' endpoint
            //string _graphAPIEndpoint = "https://graph.microsoft.com/v1.0/me";
            string _graphAPIEndpoint = "https://graph.windows.net/v1.0/me";

            //Set the scope for API call to user.read
            string[] _scopes = new string[] { "api://815a718e-1419-4a51-b90d-28ad6bdecac4/access_as_user"/*"user.read"*/ };

#if true
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

                if (authResult != null)
                {
                    var s = await GetHttpContentWithToken(_graphAPIEndpoint, authResult.AccessToken);
                    Console.WriteLine(s);
                }
            }

            public async Task<string> GetHttpContentWithToken(string url, string token)
            {
                var httpClient = new System.Net.Http.HttpClient();
#if true
                httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
                HttpResponseMessage response = await httpClient.GetAsync(todoListBaseAddress + "/api/todolist");

                string todoArray = "?";
                if (response.IsSuccessStatusCode)
                {
                    todoArray = await response.Content.ReadAsStringAsync();
                    Console.WriteLine(todoArray);
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

                return todoArray;
#else
                System.Net.Http.HttpResponseMessage response;
                try
                {
                    var request = new System.Net.Http.HttpRequestMessage(System.Net.Http.HttpMethod.Get, url);
                    //Add the token in Authorization header
                    request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
                    response = await httpClient.SendAsync(request);
                    var content = await response.Content.ReadAsStringAsync();
                    return content;
                }
                catch (Exception ex)
                {
                    return ex.ToString();
                }
#endif
            }
#endif
        }

        static void Main(string[] args)
        {
            new Test().Run().Wait();
        }
    }
}
