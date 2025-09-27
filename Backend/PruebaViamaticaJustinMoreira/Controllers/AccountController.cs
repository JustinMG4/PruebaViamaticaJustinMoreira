using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using PruebaViamaticaJustinMoreira.DTOs;
using PruebaViamaticaJustinMoreira.Exceptions;
using PruebaViamaticaJustinMoreira.Interfaces;
using PruebaViamaticaJustinMoreira.Models;
using PruebaViamaticaJustinMoreira.Services;
using System.Security.Claims;

namespace PruebaViamaticaJustinMoreira.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AccountController : ControllerBase
    {
        private readonly IAccountService _accountService;
        private readonly ILogger<AccountController> _logger;
        private readonly UserManager<User> _userManager;
        private readonly IWebHostEnvironment _env;

        public AccountController(IAccountService authService, ILogger<AccountController> logger, UserManager<User> userManager, IWebHostEnvironment env)
        {
            _accountService = authService;
            _logger = logger;
            _userManager = userManager;
            _env = env;
        }

        /// <summary>
        /// Registrar nuevo usuario
        /// </summary>
        [HttpPost("register")]
        public async Task<ActionResult<ApiResponse<object>>> Register([FromBody] RegisterDto registerDto)
        {
            _logger.LogInformation("Iniciando registro de usuario: {EmailOrUsername}", registerDto.Email);

            var result = await _accountService.RegisterAsync(registerDto, "User");

            if (result.Succeeded)
            {
                _logger.LogInformation("Usuario registrado exitosamente: {EmailOrUsername}", registerDto.Email);
                return Ok(ApiResponse<object>.SuccessResponse(
                    new { message = "Usuario registrado exitosamente" },
                    "Registro completado"
                ));
            }

            var errors = result.Errors.Select(e => e.Description).ToList();
            _logger.LogWarning("Error en registro de usuario {EmailOrUsername}: {Errors}", registerDto.Email, string.Join(", ", errors));

            return BadRequest(ApiResponse<object>.ErrorResponse(
                "Error en el registro",
                errors
            ));
        }

        [HttpPost("register-bulk")]
        [Authorize(Roles = "Admin")] // <-- Asegura que solo los administradores puedan usarlo
        public async Task<IActionResult> RegisterBulk([FromBody] List<RegisterDto> users)
        {
            if (users == null || !users.Any())
            {
                return BadRequest(new { Message = "La lista de usuarios no puede estar vacía." });
            }

            // Llama al nuevo método del servicio, asignando un rol por defecto a los usuarios cargados
            var result = await _accountService.RegisterBulkAsync(users, "User");

            if (result.FailedRegisters > 0 && result.SuccessfulRegisters == 0)
            {
                // Si todos fallaron, podría ser un 400 Bad Request
                return BadRequest(result);
            }

            // Si algunos o todos tuvieron éxito, es un 200 OK con el resumen
            return Ok(result);
        }

        /// <summary>
        /// Registrar nuevo usuario
        /// </summary>
        [HttpPost("register-admin")]
        [Authorize(Roles = "Admin")]

        public async Task<ActionResult<ApiResponse<object>>> RegisterAdmin([FromBody] RegisterDto registerDto)
        {
            _logger.LogInformation("Iniciando registro de Admin: {EmailOrUsername}", registerDto.Email);

            var result = await _accountService.RegisterAsync(registerDto, "Admin");

            if (result.Succeeded)
            {
                _logger.LogInformation("Usuario Admin registrado exitosamente: {EmailOrUsername}", registerDto.Email);
                return Ok(ApiResponse<object>.SuccessResponse(
                    new { message = "Usuario Administrador registrado exitosamente" },
                    "Registro completado"
                ));
            }

            var errors = result.Errors.Select(e => e.Description).ToList();
            _logger.LogWarning("Error en registro de usuario administrador {EmailOrUsername}: {Errors}", registerDto.Email, string.Join(", ", errors));

            return BadRequest(ApiResponse<object>.ErrorResponse(
                "Error en el registro",
                errors
            ));
        }

        /// <summary>
        /// Iniciar sesión
        /// </summary>
        [HttpPost("login")]
        public async Task<ActionResult<ApiResponse<object>>> Login([FromBody] LoginDto loginDto)
        {
            _logger.LogInformation("Intento de login para usuario: {EmailOrUsername}", loginDto.EmailOrUsername);

            var token = await _accountService.LoginAsync(loginDto);

            _logger.LogInformation("Login exitoso para usuario: {EmailOrUsername}", loginDto.EmailOrUsername);

            return Ok(ApiResponse<object>.SuccessResponse(
                new
                {
                    token = token,
                    message = "Login exitoso",
                    expiresIn = "1 hour"
                },
                "Autenticación exitosa"
            ));
        }

        /// <summary>
        /// Cerrar sesión
        /// </summary>
        [HttpPost("logout")]
        [Authorize]
        public async Task<ActionResult<ApiResponse<object>>> Logout()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);

            _logger.LogInformation("Cerrando sesión para usuario: {UserId}", userId);

            var result = await _accountService.LogoutAsync(userId);

            if (result)
            {
                _logger.LogInformation("Sesión cerrada exitosamente para usuario: {UserId}", userId);
                return Ok(ApiResponse<object>.SuccessResponse(
                    new { message = "Sesión cerrada correctamente" },
                    "Logout exitoso"
                ));
            }

            return BadRequest(ApiResponse<object>.ErrorResponse("No se encontró sesión activa"));
        }

        /// <summary>
        /// Obtener información del usuario autenticado
        /// </summary>
        [HttpGet("me")]
        [Authorize]
        public async Task<IActionResult> GetCurrentUser()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var user = await _accountService.GetUserByIdAsync(userId);

            if (user == null)
                return NotFound(ApiResponse<object>.ErrorResponse("Usuario no encontrado"));

            var person = await _accountService.GetPersonByUserIdAsync(userId);

            if (person == null)
                return NotFound(ApiResponse<object>.ErrorResponse("Información personal no encontrada"));
            var userData = new
            {
                id = user.Id,
                name = person.Name,
                lastName = person.LastName,
                identification = person.Identification,
                platformMail = person.PlatformMail,
                birthDate = person.BirthDate,
                userName = user.UserName,
                email = user.Email,
                fechaRegistro = user.DateOfRegister,
                emailConfirmed = user.EmailConfirmed,
                roles = User.FindAll(ClaimTypes.Role).Select(c => c.Value).ToList()
            };

            return Ok(ApiResponse<object>.SuccessResponse(userData, "Información de usuario"));
        }

        /// <summary>
        /// Verificar estado de bloqueo del usuario
        /// </summary>
        [HttpGet("lockout-status/{dto}")]
        public async Task<ActionResult<ApiResponse<object>>> GetLockoutStatus(string email)
        {
            // Este endpoint es útil para mostrar información de bloqueo sin autenticar
            var user = await _accountService.GetUserByEmailAsync(email);

            if (user == null)
                return NotFound(ApiResponse<object>.ErrorResponse("Usuario no encontrado"));

            var isLockedOut = await _accountService.IsUserLockedOutAsync(user.Id);
            var lockoutEnd = await _accountService.GetLockoutEndAsync(user.Id);
            var failedAttempts = await _accountService.GetFailedAttemptsAsync(user.Id);

            var lockoutInfo = new
            {
                isLockedOut = isLockedOut,
                lockoutEnd = lockoutEnd,
                failedAttempts = failedAttempts,
                remainingAttempts = Math.Max(0, 3 - failedAttempts)
            };

            return Ok(ApiResponse<object>.SuccessResponse(lockoutInfo, "Estado de bloqueo"));
        }

        /// <summary>
        /// Endpoint para que administradores desbloqueen usuarios
        /// </summary>
        [HttpPost("unlock-user/{userId}")]
        [Authorize(Roles = "Admin")]
        public async Task<ActionResult<ApiResponse<object>>> UnlockUser(string userId)
        {
            var adminId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            _logger.LogInformation("Admin {AdminId} desbloqueando usuario {UserId}", adminId, userId);

            var result = await _accountService.UnlockUserAsync(userId);

            if (result)
            {
                _logger.LogInformation("Usuario {UserId} desbloqueado exitosamente por admin {AdminId}", userId, adminId);
                return Ok(ApiResponse<object>.SuccessResponse(
                    new { message = "Usuario desbloqueado exitosamente" },
                    "Desbloqueo exitoso"
                ));
            }

            return BadRequest(ApiResponse<object>.ErrorResponse("Error al desbloquear usuario"));
        }
        /// <summary>
        /// Endpoint para que administradores desbloqueen usuarios
        /// </summary>
        [HttpPost("lock-user/{userId}")]
        [Authorize(Roles = "Admin")]
        public async Task<ActionResult<ApiResponse<object>>> LockUser(string userId)
        {
            var adminId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            _logger.LogInformation("Admin {AdminId} desbloqueando usuario {UserId}", adminId, userId);

            var result = await _accountService.LockedAccountAsync(userId,15);

            if (result)
            {
                _logger.LogInformation("Usuario {UserId} bloqueado exitosamente por admin {AdminId}", userId, adminId);
                return Ok(ApiResponse<object>.SuccessResponse(
                    new { message = "Usuario bloqueado exitosamente" },
                    "Bloqueo exitoso"
                ));
            }

            return BadRequest(ApiResponse<object>.ErrorResponse("Error al bloquear usuario"));
        }

        /// <summary>
        /// Solicitar restablecimiento de contraseña
        /// </summary>
        [HttpPost("forgot-password")]
        public async Task<ActionResult<ApiResponse<string>>> ForgotPassword([FromBody] ForgotPasswordDto dto)
        {
            _logger.LogInformation("Solicitud de restablecimiento de contraseña para: {EmailOrUsername}", dto.email);

            var result = await _accountService.ForgotPassword(dto);

            _logger.LogInformation("Enlace de restablecimiento enviado para: {EmailOrUsername}", dto.email);

            return Ok(result);
        }

        /// <summary>
        /// Restablecer contraseña con token
        /// </summary>
        [HttpPost("reset-password")]
        public async Task<ActionResult<ApiResponse<string>>> ResetPassword([FromBody] ResetPassword request)
        {
            _logger.LogInformation("Restablecimiento de contraseña para: {EmailOrUsername}", request.Email);

            var result = await _accountService.ResetPassword(request);

            _logger.LogInformation("Contraseña restablecida exitosamente para: {EmailOrUsername}", request.Email);

            return Ok(result);
        }

        /// <summary>
        /// Actualizar información básica del usuario
        /// </summary>
        [HttpPut("me/update")]
        [Authorize]
        public async Task<ActionResult<ApiResponse<object>>> UpdateUser([FromBody] UpdateUserDto updateDto)
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            
            _logger.LogInformation("Usuario {CurrentUserId} actualizando información de usuario {UserId}", userId, userId);

            var result = await _accountService.UpdateUserAsync(userId, updateDto);

            _logger.LogInformation("Usuario {UserId} actualizado exitosamente", userId);

            return Ok(result);
        }

        /// <summary>
        /// Actualizar información básica del usuario
        /// </summary>
        [HttpPut("update")]
        [Authorize(Roles = "Admin")]
        public async Task<ActionResult<ApiResponse<object>>> UpdateUsers(string userId, [FromBody] UpdateUserDto updateDto)
        {
            // Verificar si el usuario es administrador
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return NotFound(ApiResponse<object>.ErrorResponse("Usuario no encontrado"));
            }

            var roles = await _userManager.GetRolesAsync(user);
            if (roles.Contains("Admin"))
            {
                return BadRequest(new BusinessException("No puede modificar los datos de otro administrador"));
            }

            _logger.LogInformation("Usuario {CurrentUserId} actualizando información de usuario {UserId}", userId, userId);

            var result = await _accountService.UpdateUserAsync(userId, updateDto);

            _logger.LogInformation("Usuario {UserId} actualizado exitosamente", userId);

            return Ok(result);
        }

        [HttpPost("ResetPassword")]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword([FromForm] ResetPassword request, [FromForm] string confirmPassword)
        {
            if (request.Password != confirmPassword)
                return BadRequest("Las contraseñas no coinciden.");

            return Ok(await _accountService.ResetPassword(request));
        }

        [HttpGet("ResetPasswordForm")]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPasswordForm([FromQuery] string email, [FromQuery] string token)
        {
            string path = Path.Combine(_env.ContentRootPath, "Templates", "ResetPasswordForm.html");
            _logger.LogInformation(path);
            if (!System.IO.File.Exists(path))
                return NotFound("Plantilla no encontrada.");

            string htmlContent = await System.IO.File.ReadAllTextAsync(path);

            htmlContent = htmlContent
                .Replace("{{dto}}", email)
                .Replace("{{token}}", token);

            return Content(htmlContent, "text/html");
        }
    }
}
