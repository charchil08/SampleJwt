using DemoJwtApp.Services.Interface;

namespace DemoJwtApp.Middleware
{
    public class JwtMiddleware : IMiddleware
    {
        //private readonly RequestDelegate _next;
        private readonly IJwtService _jwtService;
        private readonly ILogger<JwtMiddleware> _logger;

        public JwtMiddleware(IJwtService jwtService, ILogger<JwtMiddleware> logger)
        {
            //_next = next;
            _jwtService = jwtService;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context, RequestDelegate next)
        {
            //string? tokenName = context.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();
            //var token = context.Request.Cookies["jwt"];
            var token = context.Request.Cookies["jwt"] ?? context.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();
            if (!string.IsNullOrEmpty(token))
            {
                try
                {
                    var principal = _jwtService.ValidateJwtToken(token);
                    if (principal != null)
                    {
                        context.User = principal;
                        await next(context);
                        return;
                    }
                }
                catch (Exception)
                {
                    // Log the error
                    _logger.LogInformation("Token is null or invalid");
                }
            }

            context.Response.StatusCode = 401;
            await context.Response.WriteAsync("Unauthorized");
            await next(context);
        }
    }
}
