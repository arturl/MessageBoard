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
        /// <summary>
        /// User who send the bot a message
        /// </summary>
        public string Sender;

        /// <summary>
        /// Text of the message
        /// </summary>
        public string Text;

        /// <summary>
        /// What Url in Message Board to send response to
        /// </summary>
        public string ReplyTo;
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
                    TokenValidation.Tokens.ValidateToken(jwtToken, secret);

                    var requestText = await Request.Content.ReadAsStringAsync();
                    var message = JsonConvert.DeserializeObject<Message>(requestText);

                    // Process the input
                    var result = Adder.Process(message.Text);

                    // Send the result back to the sender

                    var httpClient = new HttpClient();
                    httpClient.Timeout = TimeSpan.FromMinutes(60);

                    httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", TokenValidation.Tokens.MakeToken(secret, botId));
                    var reply = new { Sender = botId, Recipient = message.Sender, Text = result };
                    var content = new StringContent(JsonConvert.SerializeObject(reply));
                    HttpResponseMessage response = await httpClient.PostAsync(message.ReplyTo, content);

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
