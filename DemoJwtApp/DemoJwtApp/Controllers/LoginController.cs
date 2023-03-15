using DemoJwtApp.Entities;
using DemoJwtApp.Models;
using DemoJwtApp.Services;
using DemoJwtApp.Services.Interface;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace DemoJwtApp.Controllers
{
    public class LoginController : Controller
    {
        private readonly IJwtService _jwtService;

        public LoginController(IJwtService jwtService)
        {
            _jwtService = jwtService;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult UserNotFound()
        {
            return View();
        }

        [HttpPost]
        public IActionResult Login([FromBody] LoginViewModel model)
        {
            var user = AuthenticateUser(model.Username, model.Password);
            if (user == null)
            {
                return Unauthorized("User unautorized");
            }

            // Generate a JWT token for the user
            var token = _jwtService.GenerateJwtToken(user);

            // Create a cookie 
            //Todo: add an expiry minutes
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = DateTime.UtcNow.AddMinutes(60),
                SameSite = SameSiteMode.Strict
            };
            Response.Cookies.Append("jwt", token, cookieOptions);
            return Ok(new { token });
        }

        private static User? AuthenticateUser(string username, string password)
        {
            // Authenticate the user based on the username and password
            // ...
            if(username == "charchil" && password == "Password123")
            {
                return new User()
                {
                    Id = 1,
                    Role = "user",
                    Username = username,
                };
            }
            return null;
        }

    }
}
