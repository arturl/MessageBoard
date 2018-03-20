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
using System.Web;
using System.Web.Http;
using System.Web.Mvc;
using System.Web.Optimization;
using System.Web.Routing;

// The following using statements were added for this sample.
using System.Net.Http;
using System.IdentityModel.Tokens;
using System.Threading.Tasks;
using System.Threading;
using System.Net;
using System.IdentityModel.Selectors;
using System.Security.Claims;
using System.Net.Http.Headers;
using System.IdentityModel.Metadata;
using System.ServiceModel.Security;
using System.Xml;
using System.Security.Cryptography.X509Certificates;
using System.Globalization;
using System.Configuration;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Identity.Client;

namespace MessageBoardService
{
    public class WebApiApplication : System.Web.HttpApplication
    {
        protected void Application_Start()
        {
            AreaRegistration.RegisterAllAreas();
            GlobalConfiguration.Configure(WebApiConfig.Register);
            FilterConfig.RegisterGlobalFilters(GlobalFilters.Filters);
            RouteConfig.RegisterRoutes(RouteTable.Routes);
            BundleConfig.RegisterBundles(BundleTable.Bundles);
        }
    }
}
