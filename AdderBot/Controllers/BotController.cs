using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using System.Web.Http;
using Newtonsoft.Json;

namespace AdderBot.Controllers
{
    public class Message
    {
        public string Sender;
        public string Text;
        public string ReplyUrl;
    }

    public class BotController : ApiController
    {
        private const string botId  = "adder";
        private const string secret = "kWMIOrv3F6HNK5jcBojoSqSJnwjbra8o";

        public async Task<HttpResponseMessage> Post()
        {
            AuthenticationHeaderValue authHeader = Request.Headers.Authorization;
            var jwtToken = authHeader?.Parameter;
            if (jwtToken != null)
            {
                try
                {
                    var validatedToken = TokenValidation.Tokens.ValidateToken(jwtToken, secret);

                    var requestText = await Request.Content.ReadAsStringAsync();
                    var message = JsonConvert.DeserializeObject<Message>(requestText);

                    // Process the input
                    var result = Adder.Process(message.Text);

                    // Send the result back to the sender

                    var httpClient = new HttpClient();
                    httpClient.Timeout = TimeSpan.FromMinutes(60);

                    httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", TokenValidation.Tokens.MakeToken(secret));
                    var reply = new { Sender = botId, Recipient = message.Sender, Text = result };
                    var content = new StringContent(JsonConvert.SerializeObject(message));
                    HttpResponseMessage response = await httpClient.PostAsync(message.ReplyUrl, content);

                    return response;
                }
                catch
                {
                    return new HttpResponseMessage(HttpStatusCode.Unauthorized);
                }
            }
            return new HttpResponseMessage(HttpStatusCode.Unauthorized);
        }
    }
}
