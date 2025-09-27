using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using PruebaViamaticaJustinMoreira.Data;
using PruebaViamaticaJustinMoreira.DTOs;
using PruebaViamaticaJustinMoreira.Exceptions;
using PruebaViamaticaJustinMoreira.Interfaces;
using PruebaViamaticaJustinMoreira.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text;

namespace PruebaViamaticaJustinMoreira.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;
        private readonly ApplicationDbContext _context;
        private readonly IConfiguration _configuration;
        private readonly IWebHostEnvironment _env;

        public AuthService(
        UserManager<User> userManager,
        SignInManager<User> signInManager,
        ApplicationDbContext context,
        IConfiguration configuration,
        IWebHostEnvironment env)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _context = context;
            _configuration = configuration;
            _env = env;
        }

        public async Task<IdentityResult> RegisterAsync(RegisterDto registerDto)
        {
            // Aplicar todas las validaciones antes de crear el usuario
            await ValidateRegisterDataAsync(registerDto);

            // Iniciar transacción para asegurar atomicidad
            using var transaction = await _context.Database.BeginTransactionAsync();

            try
            {
                var user = new User
                {
                    UserName = registerDto.UserName,
                    Email = registerDto.Email,
                    EmailConfirmed = true,
                    DateOfRegister = DateTime.UtcNow
                };

                // Crear usuario con UserManager (esto maneja su propia conexión)
                var result = await _userManager.CreateAsync(user, registerDto.Password);

                if (!result.Succeeded)
                {
                    await transaction.RollbackAsync();
                    return result;
                }

                // Asignar rol por defecto
                var roleResult = await _userManager.AddToRoleAsync(user, "User");
                if (!roleResult.Succeeded)
                {
                    await transaction.RollbackAsync();
                    return roleResult;
                }

                // Crear persona asociada
                var persona = new Person
                {
                    IdPerson = $"USR-{DateTime.Now:yyyyMMdd}-{user.Id[..8]}",
                    Name = registerDto.Name,
                    LastName = registerDto.LastName,
                    Identification = registerDto.Identification,
                    BirthDate = registerDto.BirthDate,
                    UserId = user.Id
                };

                _context.Persons.Add(persona);
                await _context.SaveChangesAsync();

                // Si todo sale bien, confirmar la transacción
                await transaction.CommitAsync();

                return result;
            }
            catch (Exception)
            {
                // En caso de error, hacer rollback
                await transaction.RollbackAsync();
                throw;
            }
        }

        public async Task<string> LoginAsync(LoginDto loginDto)
        {
            // Validaciones de entrada
            if (string.IsNullOrEmpty(loginDto.Email) || string.IsNullOrEmpty(loginDto.Password))
                throw new ValidationException("Email y contraseña son requeridos");

            var user = await _userManager.FindByEmailAsync(loginDto.Email);
            if (user == null)
                throw new UnauthorizedException("Credenciales inválidas");

            // Requerimiento I: Un usuario solo puede tener 1 sesión activa
            var sesionActiva = await _context.Sessions
                .FirstOrDefaultAsync(s => s.UserId == user.Id && s.LogoutDate == null);

            if (sesionActiva != null)
                throw new BusinessException("Ya existe una sesión activa para este usuario");

            // Verificar si el usuario está bloqueado
            if (await _userManager.IsLockedOutAsync(user))
            {
                var lockoutEnd = await _userManager.GetLockoutEndDateAsync(user);
                throw new UnauthorizedException($"Usuario bloqueado hasta: {lockoutEnd}");
            }

            // Requerimiento IV: Bloqueo después de 3 intentos fallidos
            var result = await _signInManager.CheckPasswordSignInAsync(user, loginDto.Password, lockoutOnFailure: true);

            if (result.IsLockedOut)
            {
                throw new UnauthorizedException("Usuario bloqueado después de múltiples intentos fallidos. Intente más tarde.");
            }

            if (!result.Succeeded)
            {
                var failedAttempts = await _userManager.GetAccessFailedCountAsync(user);
                var remainingAttempts = 3 - failedAttempts;

                if (remainingAttempts > 0)
                    throw new UnauthorizedException($"Credenciales inválidas. Le quedan {remainingAttempts} intentos");
                else
                    throw new UnauthorizedException("Credenciales inválidas");
            }

            try
            {
                // Requerimiento II: Registrar inicio de sesión
                var sesion = new Session
                {
                    UserId = user.Id,
                    StartDate = DateTime.UtcNow
                };

                _context.Sessions.Add(sesion);

                // Cerrar cualquier sesión que pudiera haber quedado abierta (por seguridad)
                var sesionesAbiertas = await _context.Sessions
                    .Where(s => s.UserId == user.Id && s.LogoutDate == null && s.SessionId != sesion.SessionId)
                    .ToListAsync();

                foreach (var sesionAbierta in sesionesAbiertas)
                {
                    sesionAbierta.LogoutDate = DateTime.UtcNow;
                }

                await _context.SaveChangesAsync();

                // Resetear contador de intentos fallidos tras login exitoso
                await _userManager.ResetAccessFailedCountAsync(user);

                // Generar JWT token
                return await GenerateJwtToken(user);
            }
            catch (Exception ex)
            {
                throw new BusinessException("Error interno durante el proceso de autenticación");
            }

        }

        public async Task<bool> LogoutAsync(string userId)
        {
            var sesionActiva = await _context.Sessions
                .FirstOrDefaultAsync(s => s.UserId == userId && s.LogoutDate == null);

            if (sesionActiva != null)
            {
                sesionActiva.LogoutDate = DateTime.UtcNow;
                await _context.SaveChangesAsync();
                return true;
            }

            return false;
        }

        public async Task<User> GetUserByIdAsync(string userId)
        {
            if (string.IsNullOrWhiteSpace(userId))
                throw new ValidationException("El identificador de usuario es requerido.");

            var user = await _userManager.FindByIdAsync(userId);

            if (user == null)
                throw new NotFoundException("Usuario no encontrado.");

            return user;
        }

        public async Task<Person> GetPersonByUserIdAsync(string userId)
        {
            if (string.IsNullOrWhiteSpace(userId))
                throw new ValidationException("El identificador de usuario es requerido.");

            var person = await _context.Persons
                .FirstOrDefaultAsync(p => p.UserId == userId);

            if (person == null)
                throw new NotFoundException("No se encontró una persona asociada al usuario especificado.");

            return person;

        }


        public async Task<bool> IsUserLockedOutAsync(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null) return false;

            return await _userManager.IsLockedOutAsync(user);
        }

        private async Task<string> GenerateJwtToken(User user)
        {
            var roles = await _userManager.GetRolesAsync(user);

            var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id),
            new Claim(ClaimTypes.Email, user.Email),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.Now.AddHours(1),
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public async Task<User> GetUserByEmailAsync(string email)
        {
            if (string.IsNullOrWhiteSpace(email))
                throw new ValidationException("El mail electrónico es requerido.");

            var user = await _userManager.FindByEmailAsync(email);

            if (user == null)
                throw new NotFoundException("Usuario no encontrado con el mail proporcionado.");

            return user;
        }

        public async Task<DateTimeOffset?> GetLockoutEndAsync(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            return user != null ? await _userManager.GetLockoutEndDateAsync(user) : null;
        }

        public async Task<int> GetFailedAttemptsAsync(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            return user != null ? await _userManager.GetAccessFailedCountAsync(user) : 0;
        }

        public async Task<bool> UnlockUserAsync(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null) return false;

            var result = await _userManager.SetLockoutEndDateAsync(user, null);
            if (result.Succeeded)
            {
                await _userManager.ResetAccessFailedCountAsync(user);
            }
            return result.Succeeded;
        }

        public async Task<ApiResponse<string>> ResetPassword(ResetPassword request)
        {
            var user = _userManager.Users.FirstOrDefault(x => x.Email == request.Email)
                       ?? throw new BusinessException($"No existe cuenta registrada con el email: {request.Email}.");

            var result = await _userManager.ResetPasswordAsync(user, request.Token, request.Password);

            if (!result.Succeeded)
            {
                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                throw new BusinessException($"No se pudo restablecer la contraseña. Errores: {errors}");
            }

            return ApiResponse<string>.SuccessResponse($"Contraseña actualizada correctamente para el usuario: {user.UserName}");
        }

        public async Task<ApiResponse<string>> ForgotPassword(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
                throw new BusinessException("No existe una cuenta registrada con ese mail electrónico.");

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var encodedToken = WebUtility.UrlEncode(token);

            // Ruta del HTML
            string path = Path.Combine(_env.ContentRootPath, "Templates", "forgotPassword.html");
            if (!File.Exists(path))
                throw new BusinessException("Plantilla de mail no encontrada.");

            string content = await File.ReadAllTextAsync(path);

            string resetUrlForm = $"https://localhost:7228/api/Auth/ResetPasswordForm?email={email}&token={encodedToken}";

            string bodyHtml = content
                .Replace("{{userName}}", user.UserName)
                .Replace("{{resetUrl}}", resetUrlForm);

            var mail = new MailDto
            {
                To = user.Email,
                Subject = "Restablecer contraseña",
                Content = bodyHtml
            };

            bool send = MailService.Send(mail);

            if (!send)
                throw new BusinessException("No se pudo enviar el mail de restablecimiento de contraseña.");

            return ApiResponse<string>.SuccessResponse("Se ha send un enlace para restablecer la contraseña a tu mail electrónico.");

        }

        private async Task ValidateRegisterDataAsync(RegisterDto registerDto)
        {
            // Validar nombre de usuario
            await ValidateUserNameAsync(registerDto.UserName);

            // Validar contraseña
            ValidatePassword(registerDto.Password);

            // Validar identificación
            ValidateIdentification(registerDto.Identification);
        }

        private async Task ValidateUserNameAsync(string userName)
        {
            if (string.IsNullOrWhiteSpace(userName))
                throw new ValidationException("El nombre de usuario es requerido.");

            // a. No contener signos
            if (userName.Any(c => !char.IsLetterOrDigit(c)))
                throw new ValidationException("El nombre de usuario no debe contener signos o caracteres especiales.");

            // c. Al menos un número
            if (!userName.Any(char.IsDigit))
                throw new ValidationException("El nombre de usuario debe contener al menos un número.");

            // d. Al menos una letra mayúscula
            if (!userName.Any(char.IsUpper))
                throw new ValidationException("El nombre de usuario debe contener al menos una letra mayúscula.");

            // e. Longitud máxima de 20 dígitos y mínima de 8 dígitos
            if (userName.Length < 8 || userName.Length > 20)
                throw new ValidationException("El nombre de usuario debe tener entre 8 y 20 caracteres.");

            // b. No debe estar duplicado
            var existingUser = await _userManager.FindByNameAsync(userName);
            if (existingUser != null)
                throw new ValidationException("El nombre de usuario ya está en uso.");
        }

        private static void ValidatePassword(string password)
        {
            if (string.IsNullOrWhiteSpace(password))
                throw new ValidationException("La contraseña es requerida.");

            // a. Debe tener al menos 8 dígitos
            if (password.Length < 8)
                throw new ValidationException("La contraseña debe tener al menos 8 caracteres.");

            // b. Debe tener al menos una letra mayúscula
            if (!password.Any(char.IsUpper))
                throw new ValidationException("La contraseña debe contener al menos una letra mayúscula.");

            // c. No debe contener espacios
            if (password.Contains(' '))
                throw new ValidationException("La contraseña no debe contener espacios.");

            // d. Debe tener al menos un signo
            if (!password.Any(c => !char.IsLetterOrDigit(c)))
                throw new ValidationException("La contraseña debe contener al menos un signo o carácter especial.");
        }

        private static void ValidateIdentification(string identification)
        {
            if (string.IsNullOrWhiteSpace(identification))
                throw new ValidationException("La identificación es requerida.");

            // a. Debe tener 10 dígitos
            if (identification.Length != 10)
                throw new ValidationException("La identificación debe tener exactamente 10 dígitos.");

            // b. Solo números
            if (!identification.All(char.IsDigit))
                throw new ValidationException("La identificación solo debe contener números.");

            // c. Validar que no tenga seguido 4 veces seguidas un número
            if (HasConsecutiveRepeatedDigits(identification, 4))
                throw new ValidationException("La identificación no puede tener 4 dígitos consecutivos iguales.");
        }

        private static bool HasConsecutiveRepeatedDigits(string text, int maxConsecutive)
        {
            if (string.IsNullOrEmpty(text) || text.Length < maxConsecutive)
                return false;

            for (int i = 0; i <= text.Length - maxConsecutive; i++)
            {
                char currentChar = text[i];
                bool allSame = true;

                for (int j = 1; j < maxConsecutive; j++)
                {
                    if (text[i + j] != currentChar)
                    {
                        allSame = false;
                        break;
                    }
                }

                if (allSame)
                    return true;
            }

            return false;
        }
    }


}
