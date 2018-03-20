using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace MessageBoardService
{
    public class Bot
    {
        /// <summary>
        /// Unique ID for this bot
        /// </summary>
        public string Id;

        /// <summary>
        /// Symmetric per-bot key for signing JWT tokens.
        /// </summary>
        public string Secret;

        /// <summary>
        /// Address to which POST messages to the bot
        /// </summary>
        public string Url;

        /// <summary>
        /// What this bot can do
        /// </summary>
        public string Description;
    }
}