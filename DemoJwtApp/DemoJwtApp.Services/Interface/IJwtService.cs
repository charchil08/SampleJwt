using DemoJwtApp.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace DemoJwtApp.Services.Interface
{
    public interface IJwtService
    {
        string GenerateJwtToken(User user);
        ClaimsPrincipal? ValidateJwtToken(string token);
    }
}
