//----------------------------------------------------------------------------------------------
//    Copyright 2014 Microsoft Corporation
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.
//----------------------------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;

// The following using statements were added for this sample.
using System.Collections.Concurrent;
using MessageBoardService.Models;
using System.Security.Claims;
using System.Web;
using System.Threading.Tasks;
using Newtonsoft.Json;
using System.Net.Http.Headers;
using TokenValidation;

namespace MessageBoardService.Controllers
{
    public class Message
    {
        public string Sender;
        public string Recipient;
        public string Text;
        public override string ToString()
        {
            return $"{Sender} -> {Recipient}: '{Text}'";
        }
    }

    public class MessageBoardController : ApiController
    {
        static object messagesLock = new object();
        static List<Message> messages = new List<Message>();

        static MessageBoardController()
        {
            // Data for testing
            messages.Add(new Message { Sender = "Fred@hotmail.com", Recipient = "arturl@microsoft.com", Text = "Hello from Fred" });
            messages.Add(new Message { Sender = "Bubba@hotmail.com", Recipient = "arturl@microsoft.com", Text = "Hello from Bubba" });
            messages.Add(new Message { Sender = "Fred@hotmail.com", Recipient = "someone@microsoft.com", Text = "Hello from Fred" });

            // Known bots. Normally, this data would be stored in a persistent store
            // In this sample, keep it hard-coded for simplicity
            bots.Add(new Bot { Id = "adder", Secret = "kWMIOrv3F6HNK5jcBojoSqSJnwjbra8o", Url = "http://localhost:58343/api/bot", Description = "Can add numbers and predict weather. Just kidding about the weather" });
            bots.Add(new Bot { Id = "bot37", Secret = "hfEEGaOvBt8K8HKOaKBuf72QwyhIAxMT", Url = "http://localhost:58345/api/bot", Description = "Can do something" });
        }

        public async Task<IEnumerable<Message>> Get()
        {
            var user = await TokenValidatorHandler2.ValidateTokenInHttpRequest(Request);
            lock (messagesLock)
            {
                // Extract user messages
                var usersMessages = messages.Where(m => m.Recipient == user).ToList();
                // Remove them from the message list
                messages = messages.Where(m => m.Recipient != user).ToList();
                return usersMessages;
            }
        }

        static List<Bot> bots = new List<Bot>();

        public async Task<HttpResponseMessage> Post()
        {
            var user = await TokenValidatorHandler2.ValidateTokenInHttpRequest(Request);
            var messageText = await Request.Content.ReadAsStringAsync();
            var message = JsonConvert.DeserializeObject<Message>(messageText);

            var findBots = bots.Where(b => b.Id == message.Recipient);

            if (findBots.Any())
            {
                var bot = findBots.First();
                // This message goes to a bot. Forward it to the bot (with a different Auth token) and not store it
                var httpClient = new HttpClient();

                httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", Tokens.MakeToken(bot.Secret));
                var content = new StringContent(JsonConvert.SerializeObject(message));
                HttpResponseMessage response = await httpClient.PostAsync(bot.Url, content);
                return response;
            }
            else
            {
                // The recipient is a human. Store the message -- it will be picked up by the user later
                lock (messagesLock)
                {
                    messages.Add(message);
                }
            }

            return Request.CreateResponse(HttpStatusCode.Created);
        }
    }
}
