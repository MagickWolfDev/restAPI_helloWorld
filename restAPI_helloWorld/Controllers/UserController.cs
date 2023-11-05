using Microsoft.AspNetCore.Mvc;
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
    public class UserController : ControllerBase
    {
        private readonly IConfiguration _config;
        public UserController(IConfiguration config)
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

        [Authorize]
        [HttpGet(Name = "GetUser")]

        public dynamic Get(int id)
        {
            using (ApplicationContext db = new ApplicationContext())
            {
                var User = db.Users.Where(user => user.Id == id).FirstOrDefault();
                if (User == null)
                {
                    Response.StatusCode = 404;
                    return new { message = "user not found"};
                }
                    
                Response.StatusCode = 200;
                return new
                {
                    User.Id,
                    User.Login,
                };
            }
        }

        [HttpPost(Name = "SetUser")]
        public dynamic Post(string Login, string Password)
        {
            if(Login == null || Password == null)
            {
                Response.StatusCode = 404;
                return new { message = "bad request" };
            }

            using (ApplicationContext db = new ApplicationContext())
            {
                var User = db.Users.Where(user => user.Login == Login).FirstOrDefault();
                if (User != null)
                    return new ApiError(404, "user already exists");
            }

            try
            {
                string HashPassword = BCrypt.Net.BCrypt.HashPassword(Password);

                using (ApplicationContext db = new ApplicationContext())
                {
                    User user = new User { Login = Login, Password = HashPassword };
                    db.Users.Add(user);
                    db.SaveChanges();

                    return GenerateToken(user);
                }

            } 
            catch (Exception error)
            {
           
                return new ApiError(500, "500 iternal server error" + error.Message);
            }
            
        }
    }
}
