using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using apbd11_jwt_auth.Helpers;
using apbd11_jwt_auth.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace apbd11_jwt_auth.Controllers;

[Route("api")]
[ApiController]
public class UsersController : ControllerBase
{
    private readonly IConfiguration _configuration;
    private readonly AppDbContext _context;

    public UsersController(IConfiguration configuration, AppDbContext context)
    {
        _configuration = configuration;
        _context = context;
    }
    
    
    
    // register - add user to db
    [AllowAnonymous]
    [HttpPost("register")]
    public IActionResult Register(RegisterRequest request)
    {
        var hashedPasswordAndSalt = SecurityHelpers.GetHashedPasswordAndSalt(request.Password);
        

        var user = new AppUser()
        {
            Email = request.Email,
            Login = request.Login,
            Password = hashedPasswordAndSalt.Item1,
            Salt = hashedPasswordAndSalt.Item2,
            RefreshToken = SecurityHelpers.GenerateRefreshToken(),
            RefreshTokenExp = DateTime.Now.AddDays(1)
        };

        _context.Users.Add(user);
        _context.SaveChanges();

        return Ok();
    }
    
    
    
    // login - return access token and refresh token
    [AllowAnonymous]
    [HttpPost("login")]
    public IActionResult Login(LoginRequest loginRequest)
    {
        AppUser user = _context.Users.Where(u => u.Login == loginRequest.Login).FirstOrDefault();
        if (user == null)
        {
            return Unauthorized("Invalid login");
        }

        string passwordHashFromDb = user.Password;
        string curHashedPassword = SecurityHelpers.GetHashedPasswordWithSalt(loginRequest.Password, user.Salt);

        if (passwordHashFromDb != curHashedPassword)
        {
            return Unauthorized("Invalid password");
        }


        Claim[] userClaims = new[]
        {
            new Claim(ClaimTypes.Name, user.Login),
            new Claim(ClaimTypes.Role, "user"),
            // new Claim(ClaimTypes.Role, "admin")
            //Add additional data here
        };
        
        // Retrieve the user's claims from the database
        // var userClaims = GetUserClaims(user);

        SymmetricSecurityKey key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["SecretKey"]));

        SigningCredentials creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        JwtSecurityToken token = new JwtSecurityToken(
            issuer: "https://localhost:5001",
            audience: "https://localhost:5001",
            claims: userClaims,
            expires: DateTime.Now.AddMinutes(10),
            signingCredentials: creds
        );

        // update refresh token in db
        user.RefreshToken = SecurityHelpers.GenerateRefreshToken();
        user.RefreshTokenExp = DateTime.Now.AddDays(1);
        _context.SaveChanges();

        return Ok(new
        {
            accessToken = new JwtSecurityTokenHandler().WriteToken(token),
            refreshToken = user.RefreshToken
        });
    }
    
    
    // refresh - return new access token and refresh token
    
    // testing with Postman:
    // Authorization -> Type: Bearer Token -> <access token>
    // Body -> raw -> JSON -> {"refreshToken": "<refresh token>"}
    [Authorize(AuthenticationSchemes = "IgnoreTokenExpirationScheme")]
    // [AllowAnonymous]
    [HttpPost("refresh")]
    public IActionResult Refresh(RefreshTokenRequest refreshToken)
    {
        AppUser user = _context.Users.Where(u => u.RefreshToken == refreshToken.RefreshToken).FirstOrDefault();
        if (user == null)
        {
            throw new SecurityTokenException("Invalid refresh token");
        }

        if (user.RefreshTokenExp < DateTime.Now)
        {
            throw new SecurityTokenException("Refresh token expired");
        }
        
        Claim[] userClaims = new[]
        {
            new Claim(ClaimTypes.Name, user.Login),
            new Claim(ClaimTypes.Role, "user"),
            // new Claim(ClaimTypes.Role, "admin")
            //Add additional data here
        };
        
        // Retrieve the user's claims from the database
        // var userClaims = GetUserClaims(user);

        SymmetricSecurityKey key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["SecretKey"]));

        SigningCredentials creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        JwtSecurityToken jwtToken = new JwtSecurityToken(
            issuer: "https://localhost:5001",
            audience: "https://localhost:5001",
            claims: userClaims,
            expires: DateTime.Now.AddMinutes(10),
            signingCredentials: creds
        );

        // update refresh token in db
        user.RefreshToken = SecurityHelpers.GenerateRefreshToken();
        user.RefreshTokenExp = DateTime.Now.AddDays(1);
        _context.SaveChanges();

        return Ok(new
        {
            accessToken = new JwtSecurityTokenHandler().WriteToken(jwtToken),
            refreshToken = user.RefreshToken
        });
    }
    
    // private Claim[] GetUserClaims(AppUser user)
    // {
    //     // Replace this with your own logic to retrieve the user's claims
    //     return new[]
    //     {
    //         new Claim(ClaimTypes.Name, user.Login),
    //         new Claim(ClaimTypes.Email, user.Email),
    //     };
    //     
    //     _context.
    // }
    
    [Authorize]
    [HttpGet("data")]
    public IActionResult GetData()
    {
        // var claimsFromAccessToken = User.Claims;
        return Ok("Secret data");
    }
    
    [Authorize] // uses the access token to get the user data
    [HttpGet("userData")]
    public IActionResult GetUserData()
    {
        var claimsFromAccessToken = User.Claims;
        
        var login = User.FindFirst(ClaimTypes.Name)?.Value;
        return Ok($"User data for login: {login}"); 
        // return Ok("User data");
    }

    [AllowAnonymous]
    [HttpGet("anon")]
    public IActionResult GetAnonData()
    {
        return Ok("Public data");
    }
    
    
}