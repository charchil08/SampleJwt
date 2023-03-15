using DemoJwtApp.Services.Interface;
using Microsoft.IdentityModel.Tokens;
using System.Net;

namespace DemoJwtApp.Middleware
{
    public class AuthorizationMiddleware
    {
        private readonly RequestDelegate _next;

        public AuthorizationMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            var authHeader = context.Request.Headers["Authorization"].FirstOrDefault();
            if (authHeader != null && authHeader.StartsWith("Bearer "))
            {
                var token = authHeader.Substring("Bearer ".Length).Trim();
                try
                {
                    var jwtService = context.RequestServices.GetService<IJwtService>();
                    var claimsPrincipal = jwtService?.ValidateJwtToken(token);
                    if (claimsPrincipal != null)
                    {
                        context.User = claimsPrincipal;
                        await _next.Invoke(context);
                        return;
                    }
                }
                catch (SecurityTokenException)
                {
                    // Invalid token
                }
            }
            context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
            context.Response.Headers.Append("WWW-Authenticate", "Bearer");
            context.Response.Redirect("/Home/AccessDenied");
        }

    }
}
