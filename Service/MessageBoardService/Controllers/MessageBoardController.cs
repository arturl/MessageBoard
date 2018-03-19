﻿//----------------------------------------------------------------------------------------------
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
        }

        public IEnumerable<Message> Get()
        {
            var user = ClaimsPrincipal.Current.Claims.FirstOrDefault(c => c.Type == "preferred_username")?.Value;
            lock (messagesLock)
            {
                // Extract user messages
                var usersMessages = messages.Where(m => m.Recipient == user).ToList();
                // Remove them from the message list
                messages = messages.Where(m => m.Recipient != user).ToList();
                return usersMessages;
            }
        }

        public async Task<HttpResponseMessage> Post()
        {
            var messageText = await Request.Content.ReadAsStringAsync();
            var message = JsonConvert.DeserializeObject<Message>(messageText);
            lock (messagesLock)
            {
                messages.Add(message);
            }

            return Request.CreateResponse(HttpStatusCode.Created);
        }
    }

    public class TodoListController : ApiController
    {
        //
        // To Do items list for all users.  Since the list is stored in memory, it will go away if the service is cycled.
        //
        static ConcurrentBag<TodoItem> todoBag = new ConcurrentBag<TodoItem>();

        // GET api/todolist
        public IEnumerable<TodoItem> Get()
        {
            //
            // The Scope claim tells you what permissions the client application has in the service.
            // In this case we look for a scope value of user_impersonation, or full access to the service as the user.
            //
            if (!ClaimsPrincipal.Current.FindFirst("http://schemas.microsoft.com/identity/claims/scope").Value.Contains("access_as_user"))
            {
                throw new HttpResponseException(new HttpResponseMessage { StatusCode = HttpStatusCode.Unauthorized, ReasonPhrase = "The Scope claim does not contain 'user_impersonation' or scope claim not found" });
            }

            // A user's To Do list is keyed off of the NameIdentifier claim, which contains an immutable, unique identifier for the user.
            Claim subject = ClaimsPrincipal.Current.FindFirst(ClaimTypes.NameIdentifier);

            return from todo in todoBag
                   where todo.Owner == subject.Value
                   select todo;
        }

        // POST api/todolist
        public void Post(TodoItem todo)
        {
            if (ClaimsPrincipal.Current.FindFirst("http://schemas.microsoft.com/identity/claims/scope").Value != "user_impersonation")
            {
                throw new HttpResponseException(new HttpResponseMessage { StatusCode = HttpStatusCode.Unauthorized, ReasonPhrase = "The Scope claim does not contain 'user_impersonation' or scope claim not found" });
            }

            if (null != todo && !string.IsNullOrWhiteSpace(todo.Title))
            {
                todoBag.Add(new TodoItem { Title = todo.Title, Owner = ClaimsPrincipal.Current.FindFirst(ClaimTypes.NameIdentifier).Value });
            }
        }

    }
}