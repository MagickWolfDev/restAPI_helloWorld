using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using restAPI_helloWorld.models;
using System.Runtime.Intrinsics.X86;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
namespace restAPI_helloWorld.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthorizationController : ControllerBase
    {
        private readonly IConfiguration _config;
        public AuthorizationController(IConfiguration config)
        {
            _config = config;
        }
        private string GenerateToken(User user)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier,user.Login)
            };
            var token = new JwtSecurityToken(_config["Jwt:Issuer"],
                _config["Jwt:Audience"],
                claims,
                expires: DateTime.Now.AddMinutes(15),
                signingCredentials: credentials);


            return new JwtSecurityTokenHandler().WriteToken(token);

        }


        [HttpPost(Name = "SetAutorization")]
        public dynamic Post(string login, string password)
        {
            if (login == null || password == null)
            {
                return new ApiError(404, "bed request");
            }

            using (ApplicationContext db = new ApplicationContext())
            {
                var User = db.Users.Where(user => user.Login == login).FirstOrDefault();
                if (User == null)
                    return new ApiError(404, "user not found");

                if(!BCrypt.Net.BCrypt.Verify(password, User.Password))
                {
                    return new ApiError(404, "password incorect");
                }

                return new {
                    token = GenerateToken(User),
                };
            }

            try
            {
                string HashPassword = BCrypt.Net.BCrypt.HashPassword(password);

                using (ApplicationContext db = new ApplicationContext())
                {
                    User user = new User { Login = login, Password = HashPassword };
                    db.Users.Add(user);
                    db.SaveChanges();

                    return new string[] {
                        user.Id.ToString(),
                        user.Login
                    };
                }

            }
            catch (Exception error)
            {
                return new ApiError(500, "500 iternal server error");

            }

        }
    }
}
