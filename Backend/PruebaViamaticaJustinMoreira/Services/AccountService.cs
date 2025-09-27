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
    public class AccountService : IAccountService
    {
        private readonly UserManager<User> _userManager;
        private readonly SignInManager<User> _signInManager;
        private readonly ApplicationDbContext _context;
        private readonly IConfiguration _configuration;
        private readonly IWebHostEnvironment _env;

        public AccountService(
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

        public async Task<BulkRegisterResultDto> RegisterBulkAsync(List<RegisterDto> usersToRegister, string role)
        {
            var resultSummary = new BulkRegisterResultDto();

            // Iniciar una única transacción para todo el lote
            using var transaction = await _context.Database.BeginTransactionAsync();

            try
            {
                foreach (var registerDto in usersToRegister)
                {
                    try
                    {
                        await ValidateRegisterDataAsync(registerDto);

                        var user = new User
                        {
                            UserName = registerDto.UserName,
                            Email = registerDto.Email,
                            EmailConfirmed = true,
                            DateOfRegister = DateTime.UtcNow
                        };

                        var result = await _userManager.CreateAsync(user, registerDto.Password);
                        if (!result.Succeeded)
                        {
                            resultSummary.FailedRegisters++;
                            resultSummary.Errors.AddRange(result.Errors.Select(e => $"Usuario '{registerDto.UserName}': {e.Description}"));
                            continue;
                        }

                        var roleResult = await _userManager.AddToRoleAsync(user, role);
                        if (!roleResult.Succeeded)
                        {
                            resultSummary.FailedRegisters++;
                            resultSummary.Errors.AddRange(roleResult.Errors.Select(e => $"Usuario '{registerDto.UserName}': {e.Description}"));
                            continue;
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

                        resultSummary.SuccessfulRegisters++;
                    }
                    catch (Exception ex)
                    {
                        resultSummary.FailedRegisters++;
                        resultSummary.Errors.Add($"Usuario '{registerDto.UserName}': {ex.Message}");
                    }
                }

                await _context.SaveChangesAsync();
                await transaction.CommitAsync();
            }
            catch (Exception ex)
            {
                await transaction.RollbackAsync();
                throw new Exception("Ocurrió un error catastrófico durante la carga masiva. Se revirtieron todos los cambios.", ex);
            }

            return resultSummary;
        }

        public async Task<IdentityResult> RegisterAsync(RegisterDto registerDto, string role)
        {
            await ValidateRegisterDataAsync(registerDto);

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

                var result = await _userManager.CreateAsync(user, registerDto.Password);

                if (!result.Succeeded)
                {
                    await transaction.RollbackAsync();
                    return result;
                }

                var roleResult = await _userManager.AddToRoleAsync(user, role);
                if (!roleResult.Succeeded)
                {
                    await transaction.RollbackAsync();
                    return roleResult;
                }

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

                await transaction.CommitAsync();

                return result;
            }
            catch (Exception)
            {
                await transaction.RollbackAsync();
                throw;
            }
        }

        public async Task<string> LoginAsync(LoginDto loginDto)
{
    // Validaciones de entrada
    if (string.IsNullOrEmpty(loginDto.EmailOrUsername) || string.IsNullOrEmpty(loginDto.Password))
        throw new ValidationException("Email/Usuario y contraseña son requeridos");

    // Buscar usuario por email o username
    var user = await FindUserByEmailOrUsernameAsync(loginDto.EmailOrUsername);
    if (user == null)
        throw new UnauthorizedException("Credenciales inválidas");

    // Requerimiento I: Un usuario solo puede tener 1 sesión activa
    var activeSession = await _context.Sessions
        .FirstOrDefaultAsync(s => s.UserId == user.Id && s.LogoutDate == null);

    if (activeSession != null)
        throw new BusinessException("Ya existe una sesión activa para este usuario");

    // Verificar si el usuario está bloqueado
    if (await _userManager.IsLockedOutAsync(user))
    {
        var lockoutEnd = await _userManager.GetLockoutEndDateAsync(user);
        throw new UnauthorizedException($"Usuario bloqueado hasta: {lockoutEnd}");
    }

    var currentFailedAttempts = await _userManager.GetAccessFailedCountAsync(user);

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

    using var transaction = await _context.Database.BeginTransactionAsync();

    try
    {
        // Requerimiento II: Registrar inicio de sesión
        var session = new Session
        {
            UserId = user.Id,
            StartDate = DateTime.UtcNow,
            Intents = currentFailedAttempts
        };

        _context.Sessions.Add(session);

        // Cerrar cualquier sesión que pudiera haber quedado abierta (por seguridad)
        var openSessions = await _context.Sessions
            .Where(s => s.UserId == user.Id && s.LogoutDate == null && s.SessionId != session.SessionId)
            .ToListAsync();

        foreach (var openSession in openSessions)
        {
            openSession.LogoutDate = DateTime.UtcNow;
        }

        await _context.SaveChangesAsync();

        var resetResult = await _userManager.ResetAccessFailedCountAsync(user);
        if (!resetResult.Succeeded)
        {
            await transaction.RollbackAsync();
            throw new BusinessException("Error al resetear el contador de intentos fallidos");
        }

        await transaction.CommitAsync();

        return await GenerateJwtToken(user);
    }
    catch (Exception)
    {
        // En caso de error, hacer rollback
        await transaction.RollbackAsync();
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


        public async Task<bool> LockedAccountAsync(string userId, int minutes)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null) return false;
            var lockoutEnd = DateTimeOffset.UtcNow.AddMinutes(minutes);
            var result = await _userManager.SetLockoutEndDateAsync(user, lockoutEnd);
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

        public async Task<ApiResponse<string>> ForgotPassword(ForgotPasswordDto dto)
        {
            var user = await _userManager.FindByEmailAsync(dto.email);
            if (user == null)
                throw new BusinessException("No existe una cuenta registrada con ese mail electrónico.");

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var encodedToken = WebUtility.UrlEncode(token);

            // Ruta del HTML
            string path = Path.Combine(_env.ContentRootPath, "Templates", "forgotPassword.html");
            if (!File.Exists(path))
                throw new BusinessException("Plantilla de mail no encontrada.");

            string content = await File.ReadAllTextAsync(path);

            string resetUrlForm = $"https://localhost:7228/api/Account/ResetPasswordForm?email={dto.email}&token={encodedToken}";

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

            var existingUser = await _userManager.FindByEmailAsync(registerDto.Email);
            if (existingUser != null)
                throw new ValidationException("El correo del usuario ya está en uso.");

            var existingPerson = await _context.Persons.FirstOrDefaultAsync(p => p.Identification == registerDto.Identification);
            if (existingPerson != null)
                throw new ValidationException("La persona con el numero de identificacion proporcionado ya existe.");
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
        public async Task<ApiResponse<object>> UpdateUserAsync(string userId, UpdateUserDto updateDto)
        {
            if (string.IsNullOrWhiteSpace(userId))
                throw new ValidationException("El identificador de usuario es requerido.");

            // Validar campos de entrada
            ValidateUpdateFields(updateDto);

            // Validar datos según las reglas de negocio
            await ValidateUpdateDataAsync(userId, updateDto);

            // Obtener entidades
            var user = await GetUserForUpdateAsync(userId);
            var person = await GetPersonForUpdateAsync(userId);

            // Iniciar transacción
            using var transaction = await _context.Database.BeginTransactionAsync();

            try
            {
                var updatedFields = await ApplyUpdatesAsync(user, person, updateDto);

                if (updatedFields.Count == 0)
                {
                    await transaction.RollbackAsync();
                    return ApiResponse<object>.SuccessResponse(
                        new { message = "No se detectaron cambios en los datos proporcionados." },
                        "Sin cambios"
                    );
                }

                // Guardar cambios
                await SaveUpdatesAsync(user);

                // Confirmar transacción
                await transaction.CommitAsync();

                return CreateSuccessResponse(user, person, updatedFields);
            }
            catch (Exception)
            {
                await transaction.RollbackAsync();
                throw;
            }
        }

        private async Task<User> GetUserForUpdateAsync(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                throw new NotFoundException("Usuario no encontrado.");
            return user;
        }

        private async Task<Person> GetPersonForUpdateAsync(string userId)
        {
            var person = await _context.Persons.FirstOrDefaultAsync(p => p.UserId == userId);
            if (person == null)
                throw new NotFoundException("Información personal no encontrada.");
            return person;
        }

        private async Task<List<string>> ApplyUpdatesAsync(User user, Person person, UpdateUserDto updateDto)
        {
            var updatedFields = new List<string>();

            // Actualizar UserName si es diferente
            if (!string.IsNullOrWhiteSpace(updateDto.UserName) && updateDto.UserName != user.UserName)
            {
                user.UserName = updateDto.UserName;
                updatedFields.Add("Nombre de usuario");
            }

            // Actualizar Email si es diferente
            if (!string.IsNullOrWhiteSpace(updateDto.Email) && updateDto.Email != user.Email)
            {
                user.Email = updateDto.Email;
                updatedFields.Add("EmailOrUsername");
            }

            // Actualizar Name en Person si es diferente
            if (!string.IsNullOrWhiteSpace(updateDto.Name) && updateDto.Name != person.Name)
            {
                person.Name = updateDto.Name;
                updatedFields.Add("Nombre");
            }

            return updatedFields;
        }

        private async Task SaveUpdatesAsync(User user)
        {
            var userResult = await _userManager.UpdateAsync(user);
            if (!userResult.Succeeded)
            {
                var errors = userResult.Errors.Select(e => e.Description).ToList();
                throw new BusinessException($"Error al actualizar usuario: {string.Join(", ", errors)}");
            }

            await _context.SaveChangesAsync();
        }

        private static ApiResponse<object> CreateSuccessResponse(User user, Person person, List<string> updatedFields)
        {
            return ApiResponse<object>.SuccessResponse(
                new
                {
                    message = "Usuario actualizado exitosamente",
                    updatedFields = updatedFields,
                    user = new
                    {
                        id = user.Id,
                        userName = user.UserName,
                        email = user.Email,
                        name = person.Name
                    }
                },
                "Actualización exitosa"
            );
        }

        private async Task ValidateUpdateDataAsync(string userId, UpdateUserDto updateDto)
        {
            var validationErrors = new List<string>();

            // Validar UserName si se proporciona
            if (!string.IsNullOrWhiteSpace(updateDto.UserName))
            {
                try
                {
                    await ValidateUserNameForUpdateAsync(updateDto.UserName, userId);
                }
                catch (ValidationException ex)
                {
                    validationErrors.Add(ex.Message);
                }
            }

            // Validar Email si se proporciona
            if (!string.IsNullOrWhiteSpace(updateDto.Email))
            {
                try
                {
                    await ValidateEmailForUpdateAsync(updateDto.Email, userId);
                }
                catch (ValidationException ex)
                {
                    validationErrors.Add(ex.Message);
                }
            }

            // Validar Name si se proporciona
            if (!string.IsNullOrWhiteSpace(updateDto.Name))
            {
                try
                {
                    ValidatePersonNameForUpdate(updateDto.Name);
                }
                catch (ValidationException ex)
                {
                    validationErrors.Add(ex.Message);
                }
            }

            if (validationErrors.Count > 0)
            {
                throw new ValidationException(validationErrors);
            }
        }

        private async Task ValidateUserNameForUpdateAsync(string userName, string currentUserId)
        {
            if (string.IsNullOrWhiteSpace(userName))
                throw new ValidationException("El nombre de usuario es requerido.");

            ValidateUserNameFormat(userName);

            var existingUser = await _userManager.FindByNameAsync(userName);
            if (existingUser != null && existingUser.Id != currentUserId)
                throw new ValidationException("El nombre de usuario ya está en uso por otro usuario.");
        }

        private void ValidateUserNameFormat(string userName)
        {
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
        }

        private async Task ValidateEmailForUpdateAsync(string email, string currentUserId)
        {
            if (string.IsNullOrWhiteSpace(email))
                throw new ValidationException("El email es requerido.");

            // Validar formato
            ValidateEmailFormat(email);

            // Validar duplicación específica para actualización
            var existingUser = await _userManager.FindByEmailAsync(email);
            if (existingUser != null && existingUser.Id != currentUserId)
                throw new ValidationException("El email ya está en uso por otro usuario.");
        }

        private static void ValidateEmailFormat(string email)
        {
            // Validaciones básicas de formato
            if (!email.Contains("@"))
                throw new ValidationException("El email debe contener el símbolo @.");

            if (!email.Contains("."))
                throw new ValidationException("El email debe contener al menos un punto.");

            if (email.Length < 5)
                throw new ValidationException("El email debe tener al menos 5 caracteres.");

            if (email.Length > 100)
                throw new ValidationException("El email no puede exceder 100 caracteres.");

            // Validar que no empiece o termine con @ o .
            if (email.StartsWith("@") || email.StartsWith(".") || email.EndsWith("@") || email.EndsWith("."))
                throw new ValidationException("El email no puede empezar o terminar con @ o .");
        }

        private static void ValidatePersonNameForUpdate(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
                throw new ValidationException("El nombre es requerido.");

            ValidatePersonNameFormat(name);
        }

        private static void ValidatePersonNameFormat(string name)
        {
            if (name.Length < 2)
                throw new ValidationException("El nombre debe tener al menos 2 caracteres.");

            if (name.Length > 50)
                throw new ValidationException("El nombre no puede exceder 50 caracteres.");

            // Solo letras, espacios y algunos caracteres especiales comunes en nombres
            if (!name.All(c => char.IsLetter(c) || char.IsWhiteSpace(c) || c == '\'' || c == '-'))
                throw new ValidationException("El nombre solo puede contener letras, espacios, apostrofes y guiones.");

            // No puede empezar o terminar con espacios
            if (name.Trim() != name)
                throw new ValidationException("El nombre no puede empezar o terminar con espacios.");

            // No puede tener espacios dobles
            if (name.Contains("  "))
                throw new ValidationException("El nombre no puede contener espacios dobles.");
        }

        private static void ValidateUpdateFields(UpdateUserDto updateDto)
        {
            if (string.IsNullOrWhiteSpace(updateDto.UserName) &&
                string.IsNullOrWhiteSpace(updateDto.Email) &&
                string.IsNullOrWhiteSpace(updateDto.Name))
            {
                throw new ValidationException("Debe proporcionar al menos un campo para actualizar (UserName, EmailOrUsername o Name).");
            }
        }

        private async Task<User?> FindUserByEmailOrUsernameAsync(string emailOrUsername)
        {
            var userByEmail = await _userManager.FindByEmailAsync(emailOrUsername);
            if (userByEmail != null)
                return userByEmail;

            var userByUsername = await _userManager.FindByNameAsync(emailOrUsername);
            return userByUsername;
        }

    }


}
