using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using MimeKit;
using MailKit.Net.Smtp;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using System.Text.RegularExpressions;

namespace EmailConfirmationDemo.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AccountController : ControllerBase
    {
        private readonly ILogger<AccountController> _logger;
        private readonly UserManager<IdentityUser> _userManager;

        public AccountController(ILogger<AccountController> logger, UserManager<IdentityUser> userManager)
        {
            _logger = logger;
            _userManager = userManager;
        }

        [HttpPost("register/{email}/{password}")]
        public async Task<IActionResult> Register(string email, string password)
        {
            if (!IsValidEmail(email))
            {
                return BadRequest("Invalid email format");
            }

            var user = await GetUser(email);
            if (user != null) return BadRequest("User already exists");

            var result = await _userManager.CreateAsync(new IdentityUser()
            {
                UserName = email,
                Email = email,
            }, password);

            if (!result.Succeeded) 
            {
                return BadRequest(result.Errors.Select(e => e.Description));
            }

            var _user = await GetUser(email);
            var emailCode = await _userManager.GenerateEmailConfirmationTokenAsync(_user!);
            string sendEmail = SendEmail(_user!.Email!, emailCode);
            return Ok(sendEmail);
        }

        [HttpPost("confirmation/{email}/{code}")]
        public async Task<IActionResult> Confirmation(string email, string code)
        {
            if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(code))
            {
                return BadRequest("Invalid code provided");
            }

            if (!IsValidEmail(email))
            {
                return BadRequest("Invalid email format");
            }

            var user = await GetUser(email);
            if (user == null)
            {
                return BadRequest("Invalid identity provided");
            }

            var result = await _userManager.ConfirmEmailAsync(user, code);
            if (!result.Succeeded)
            {
                return BadRequest("Invalid confirmation code provided");
            }

            return Ok("Email confirmed successfully, you can proceed to login");
        }

        [HttpPost("login/{email}/{password}")]
        public async Task<IActionResult> Login(string email, string password)
        {
            if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(password))
            {
                return BadRequest("Email and password are required");
            }

            if (!IsValidEmail(email))
            {
                return BadRequest("Invalid email format");
            }

            var user = await GetUser(email);
            if (user == null)
            {
                return BadRequest("Invalid user");
            }

            bool isEmailConfirmed = await _userManager.IsEmailConfirmedAsync(user);
            if (!isEmailConfirmed)
            {
                return BadRequest("You need to confirm your email before logging in");
            }

            return Ok(new[] { "Login successful", GenerateToken(user) });
        }

        private string GenerateToken(IdentityUser? user)
        {
            var key = Encoding.ASCII.GetBytes("Qw12ER34TY56Ui780198v2bNh78JK4Hods7uUj12");
            var securityKey = new SymmetricSecurityKey(key);
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user!.Id),
                new Claim(JwtRegisteredClaimNames.Email, user!.Email)
            };

            var token = new JwtSecurityToken(
                issuer: null,
                audience: null,
                claims: claims,
                expires: DateTime.UtcNow.AddHours(1), // 設置 1 小時過期時間
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private string SendEmail(string email, string emailCode)
        {
            StringBuilder emailMessage = new StringBuilder();

            emailMessage.AppendLine("<html>");
            emailMessage.AppendLine("<body>");
            emailMessage.AppendLine($"<p>Dear {email},</p>");
            emailMessage.AppendLine("<p>Thank you for registering with us. To verify your email address, please click the following link:</p>");
            emailMessage.AppendLine($"<h2>Verification Code: {emailCode}</h2>");
            emailMessage.AppendLine("<p>Please enter this code on our website to complete your registration.</p>");
            emailMessage.AppendLine("<p>If you did not request this, please ignore this email.</p>");
            emailMessage.AppendLine("<br>");
            emailMessage.AppendLine("<p>Best regards, </p>");
            emailMessage.AppendLine("<p><strong>Netcode-Hub</strong></p>");
            emailMessage.AppendLine("</body>");
            emailMessage.AppendLine("</html>");

            string message = emailMessage.ToString();

            var mailMessage = new MimeMessage();
            mailMessage.To.Add(MailboxAddress.Parse(email));
            mailMessage.From.Add(MailboxAddress.Parse("your-email@example.com"));

            mailMessage.Subject = "Email Confirmation";
            mailMessage.Body = new TextPart(MimeKit.Text.TextFormat.Html) { Text = message };

            using var smtp = new SmtpClient();
            smtp.Connect("smtp.server.com", 587, MailKit.Security.SecureSocketOptions.StartTls);
            smtp.Authenticate("username", "password");
            smtp.Send(mailMessage);
            smtp.Disconnect(true);

            return "Email sent successfully";
        }

        private async Task<IdentityUser?> GetUser(string email)
        {
            return await _userManager.FindByEmailAsync(email);
        }

        [HttpGet("protected")]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public string GetMessage()
        {
            return "This message is coming from protected endpoint";
        }

        private bool IsValidEmail(string email)
        {
            var emailRegex = @"^[^@\s]+@[^@\s]+\.[^@\s]+$";
            return Regex.IsMatch(email, emailRegex);
        }
    }
}
