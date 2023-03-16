using DemoJwtApp.Models;
using DemoJwtApp.Services.Interface;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Diagnostics;
using System.Security.Claims;

namespace DemoJwtApp.Controllers
{
    
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        [AllowAnonymous]
        public IActionResult Index()
        {
            return View();
        }

        [Authorize(Roles = "user")]
        public IActionResult Privacy()
        {
            //if (Response.StatusCode == 401)
            //{
            //    return BadRequest(new { Response.Body });
            //}
            // Get the authenticated user from the JWT token
            var claimsPrincipal = HttpContext.User;
            var userId = claimsPrincipal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var username = claimsPrincipal.FindFirst(ClaimTypes.Name)?.Value;
            var role = claimsPrincipal.FindFirst(ClaimTypes.Role)?.Value;

            return Ok(new { userId, username, role });
            //return View();
        }

        [AllowAnonymous]
        public IActionResult AccessDenied()
        {
            return Ok("User not found");
            //return RedirectToAction("UserNotFound", "Login");
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}