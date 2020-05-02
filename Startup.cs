using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.AzureAD.UI;
using Microsoft.AspNetCore.Authentication.AzureADB2C.UI;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using B2CMultiTenant.Models;
using B2CMultiTenant.Extensions;
using Microsoft.Identity.Client;
using System.Security.Claims;
using Microsoft.Extensions.Primitives;
using System.Web;
using Microsoft.Extensions.Logging;
using System.Diagnostics;
using Microsoft.Extensions.Hosting;

namespace B2CMultiTenant
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }
        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            var policyPrefix = Configuration.GetValue<string>("PolicyPrefix");
            services.Configure<CookiePolicyOptions>(options =>
            {
                // This lambda determines whether user consent for non-essential cookies is needed for a given request.
                options.CheckConsentNeeded = context => true;
                options.MinimumSameSitePolicy = SameSiteMode.None;
            });
            services
                .AddHttpContextAccessor()
                .AddScoped<TokenService>()
                .AddTransient<RESTService>()
                .AddAuthentication(options =>
                {
                    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                })
                    .AddCookie(options =>
                    {
                        options.LoginPath = "/Account/Unauthorized/";
                        options.AccessDeniedPath = "/Account/Forbidden/";
                    })
                    .AddOpenIdConnect("susi2", options => OptionsFor(options, "susi2"))
                    .AddOpenIdConnect("susi-firsttenant", options => OptionsFor(options, "susi-firsttenant"))
                    .AddOpenIdConnect("passwordreset", options => OptionsFor(options, "passwordreset"));

            services.Configure<ConfidentialClientApplicationOptions>(options => Configuration.Bind("AzureAD", options));

            services.AddSession(options => options.Cookie.IsEssential = true);
            services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_3_0);
        }

        private void OptionsFor(OpenIdConnectOptions options, string policy)
        {
            var policyPrefix = Configuration.GetValue<string>("PolicyPrefix");
            policy = $"{policyPrefix}{policy}";
            var aadOptions = new AzureADOptions();
            Debug.WriteLine("Domain: {0}", aadOptions.Domain);
            Configuration.Bind("AzureAD", aadOptions);
            options.ClientId = aadOptions.ClientId;
            var aadTenant = aadOptions.Domain.Split('.')[0];
            options.MetadataAddress = $"https://{aadTenant}.b2clogin.com/{aadOptions.TenantId}/b2c_1a_{policy}/v2.0/.well-known/openid-configuration";
            Debug.WriteLine("Metadata: {0}", options.MetadataAddress);
            options.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters()
            {
                NameClaimType = "name"
            };
            options.CallbackPath = new PathString($"/signin-{policy}"); // otherwise getting 'correlation error'
            options.SignedOutCallbackPath = new PathString($"/signout-{policy}");
            options.SignedOutRedirectUri = "/";
            //TODO: Code repeated in RESTService
            var scopes = new string[]
            {
                    $"https://{aadOptions.Domain}/{Configuration.GetValue<string>("RestApp")}/Members.ReadAll",
                    "offline_access"
            };
            if (policy.Contains("susi"))
            {
                options.ResponseType = OpenIdConnectResponseType.CodeIdToken;
                //TODO: Improve, Concat could not be used
                foreach (var s in scopes)
                    options.Scope.Add(s);
            }
            else
                options.ResponseType =  OpenIdConnectResponseType.IdToken;
            options.Events.OnRedirectToIdentityProvider = async (ctx) =>
            {
                if (ctx.Properties.Parameters.ContainsKey("tenant"))
                {
                    var tenantName = (string)ctx.Properties.Parameters["tenant"];
                    ctx.ProtocolMessage.Parameters.Add("tenant", tenantName);
                }
                if (ctx.Properties.Parameters.ContainsKey("domain"))
                {
                    var domainName = (string)ctx.Properties.Parameters["domain"];
                    ctx.ProtocolMessage.DomainHint = domainName;
                }
                await Task.FromResult(0);
            };
            options.Events.OnAuthorizationCodeReceived = async (ctx) =>
            {
                ctx.HandleCodeRedemption();
                Debug.WriteLine("OnAuthCode called");
                // The cache will need the claims from the ID token.
                // If they are not yet in the HttpContext.User's claims, so adding them here.
                if (!ctx.HttpContext.User.Claims.Any())
                {
                    (ctx.HttpContext.User.Identity as ClaimsIdentity).AddClaims(ctx.Principal.Claims);
                }
                var ts = ctx.HttpContext.RequestServices.GetRequiredService<Extensions.TokenService>();
                var auth = ts.AuthApp;
                var tokens = await auth.AcquireTokenByAuthorizationCode(
                    scopes,
                    ctx.ProtocolMessage.Code).ExecuteAsync().ConfigureAwait(false);
                ctx.HandleCodeRedemption(null, tokens.IdToken);
            };
            options.Events.OnRemoteFailure = (ctx) =>
            {
                ctx.HandleResponse();
                Debug.WriteLine("WebApp error called");
                Debug.WriteLine("Error details: {0}", ctx.Failure.StackTrace);
                if (!String.IsNullOrEmpty(ctx.Failure.Message))
                {
                    if (ctx.Failure.Message.Contains("AADB2C90118"))
                    {
                        ctx.Response.Redirect("/Home/PwdReset");
                    }
                    else if (ctx.Failure.Message.Contains("access_denied"))
                    {
                        // If the user canceled the sign in, redirect back to the home page
                        ctx.Response.Redirect("/");
                    }
                    else
                    {
                        ctx.Response.Redirect("/Home/Error?message=" + HttpUtility.UrlEncode(ctx.Failure.Message));
                    }
                }
                ctx.HandleResponse();
                return Task.FromResult(0);
            };
            options.Events.OnTokenValidated = (ctx) =>
            {
                var path = ctx.Principal.FindFirst("http://schemas.microsoft.com/claims/authnclassreference").Value;
                if (!path.Contains("susi")) // need to re-authenticate, may have been pwd reset
                    ctx.Response.Redirect("/Home/MemberSignIn");
                return Task.FromResult(0);
            };
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            //IdentityModelEventSource.ShowPII = true;
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();
            app.UseCookiePolicy();

            app.UseRouting();

            app.UseSession();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });

        }
    }
}
