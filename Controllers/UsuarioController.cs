using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using APICORE.Models;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using BCrypt.Net;

using System.Data.SqlClient;
using System.Data;
using Microsoft.AspNetCore.Authorization;
using APICORE.utils;

namespace APICORE.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UsuarioController : ControllerBase
    {

        private readonly string cadenaSQl;


        private IConfiguration _config;
        public UsuarioController(IConfiguration config)
        {
            _config = config;
            cadenaSQl = config.GetConnectionString("CadenaSQL");
        }

        private Users AuthenticateUser(Login login)
        {

            List<Users> lista = new List<Users>();
            Users u;


                using (var conexion = new SqlConnection(cadenaSQl))
            {

                conexion.Open();
                var cmd = new SqlCommand("select * from Usuarios", conexion);
                cmd.CommandType = CommandType.Text;


                using (var rd = cmd.ExecuteReader())
                {
                    while (rd.Read())
                    {

                        lista.Add(new Users()
                        {
                            Id = Convert.ToInt32(rd["id"]),
                            UserName = rd["username"].ToString(),
                            Password = rd["pass"].ToString(),
                            rol = rd["rol"].ToString()
                        });

                    };

                };

            };

            string cadenaEncriptada = Encrypt.GetSHA256(login.password);


            u = lista.Where(item => item.UserName == login.username && item.Password == cadenaEncriptada).FirstOrDefault();

            return u;
   
        }

        private string GenerateToken()
        {
            var securitykey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var credentials = new SigningCredentials(securitykey, SecurityAlgorithms.HmacSha256);
            var token = new JwtSecurityToken(_config["Jwt:Issuer"], _config["Jwt:Audience"], null,
                expires: DateTime.Now.AddMinutes(5), signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);

        }

        [AllowAnonymous]
        [Route("login")]
        [HttpPost]
        public IActionResult Login(Login login)
        { 

            var user_ = AuthenticateUser(login);
            
            if(user_ != null)
            {

                var token = GenerateToken();
                return StatusCode(StatusCodes.Status200OK, new { rol = user_.rol, token = token });

            }
            return StatusCode(StatusCodes.Status401Unauthorized, new { msg = "No authorizado" });

        }
    }
}
