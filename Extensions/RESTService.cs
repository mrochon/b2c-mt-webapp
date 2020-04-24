using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;

namespace B2CMultiTenant.Extensions
{
    public class RESTService
    {
        public RESTService(TokenService tokenService, IConfiguration conf)
        {
            _tokenService = tokenService;
            _conf = conf;
            Url = conf["RESTUrl"];
        }

        //public static readonly string Url = "http://localhost:57688";
        public static string Url
        {
            get;
            private set;
        }
        TokenService _tokenService;
        IConfiguration _conf;
        public async Task<HttpClient> GetClientAsync()
        {
            //TODO: code rpeated from Startup
            var tenant = _conf.GetValue<string>("AzureAD:Domain");
            var restApp = _conf.GetValue<string>("RestApp");
            var scopes = new string[]
            {
                    $"https://{tenant}/{restApp}/Members.ReadAll",
                    "offline_access"
            };
            var client = new HttpClient();
            var token = await _tokenService.GetUserTokenAsync(scopes);
            client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
            return client;
        }
    }
}
