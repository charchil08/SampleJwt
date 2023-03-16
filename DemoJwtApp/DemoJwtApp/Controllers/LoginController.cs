﻿using DemoJwtApp.Entities;
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
        private readonly IConfiguration _configuration;

        public LoginController(IJwtService jwtService, IConfiguration configuration)
        {
            _jwtService = jwtService;
            _configuration = configuration;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult UserNotFound()
        {
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Login()
        {
            //Check weather token is already available
            var token = Request.Cookies["jwt"];
            if (token != null)
            {
                TempData["NotificationMessage"] = "Your operation was successful.";
                return RedirectToAction("Index", "Home");
            }
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
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
                HttpOnly = _configuration.GetValue<bool>("RefreshToken:HttpOnly"),
                Secure = _configuration.GetValue<bool>("RefreshToken:Secure"),
                Expires = DateTime.UtcNow.AddMinutes(_configuration.GetValue<double>("RefreshToken:ExpiryMinutes")),
                SameSite = SameSiteMode.Strict
            };
            Response.Cookies.Append("jwt", token, cookieOptions);
            return Ok(new { token });
        }

        private static User? AuthenticateUser(string username, string password)
        {
            // Authenticate the user based on the username and password
            // ...
            if (username == "charchil" && password == "Password123")
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
