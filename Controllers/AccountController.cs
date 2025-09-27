using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PruebaViamaticaJustinMoreira.DTOs;
using PruebaViamaticaJustinMoreira.Interfaces;
using PruebaViamaticaJustinMoreira.Models;
using System.Security.Claims;

namespace PruebaViamaticaJustinMoreira.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AccountController : ControllerBase
    {
        private readonly IAccountService _authService;
        private readonly ILogger<AccountController> _logger;

        public AccountController(IAccountService authService, ILogger<AccountController> logger)
        {
            _authService = authService;
            _logger = logger;
        }

        /// <summary>
        /// Registrar nuevo usuario
        /// </summary>
        [HttpPost("register")]
        public async Task<ActionResult<ApiResponse<object>>> Register([FromBody] RegisterDto registerDto)
        {
            _logger.LogInformation("Iniciando registro de usuario: {Email}", registerDto.Email);

            var result = await _authService.RegisterAsync(registerDto, "User");

            if (result.Succeeded)
            {
                _logger.LogInformation("Usuario registrado exitosamente: {Email}", registerDto.Email);
                return Ok(ApiResponse<object>.SuccessResponse(
                    new { message = "Usuario registrado exitosamente" },
                    "Registro completado"
                ));
            }

            var errors = result.Errors.Select(e => e.Description).ToList();
            _logger.LogWarning("Error en registro de usuario {Email}: {Errors}", registerDto.Email, string.Join(", ", errors));

            return BadRequest(ApiResponse<object>.ErrorResponse(
                "Error en el registro",
                errors
            ));
        }

        /// <summary>
        /// Registrar nuevo usuario
        /// </summary>
        [HttpPost("register-admin")]
        [Authorize(Roles = "Admin")]

        public async Task<ActionResult<ApiResponse<object>>> RegisterAdmin([FromBody] RegisterDto registerDto)
        {
            _logger.LogInformation("Iniciando registro de Admin: {Email}", registerDto.Email);

            var result = await _authService.RegisterAsync(registerDto, "Admin");

            if (result.Succeeded)
            {
                _logger.LogInformation("Usuario Admin registrado exitosamente: {Email}", registerDto.Email);
                return Ok(ApiResponse<object>.SuccessResponse(
                    new { message = "Usuario Administrador registrado exitosamente" },
                    "Registro completado"
                ));
            }

            var errors = result.Errors.Select(e => e.Description).ToList();
            _logger.LogWarning("Error en registro de usuario administrador {Email}: {Errors}", registerDto.Email, string.Join(", ", errors));

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
            _logger.LogInformation("Intento de login para usuario: {Email}", loginDto.Email);

            var token = await _authService.LoginAsync(loginDto);

            _logger.LogInformation("Login exitoso para usuario: {Email}", loginDto.Email);

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

            var result = await _authService.LogoutAsync(userId);

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
            var user = await _authService.GetUserByIdAsync(userId);

            if (user == null)
                return NotFound(ApiResponse<object>.ErrorResponse("Usuario no encontrado"));

            var person = await _authService.GetPersonByUserIdAsync(userId);

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
        [HttpGet("lockout-status/{email}")]
        public async Task<ActionResult<ApiResponse<object>>> GetLockoutStatus(string email)
        {
            // Este endpoint es útil para mostrar información de bloqueo sin autenticar
            var user = await _authService.GetUserByEmailAsync(email);

            if (user == null)
                return NotFound(ApiResponse<object>.ErrorResponse("Usuario no encontrado"));

            var isLockedOut = await _authService.IsUserLockedOutAsync(user.Id);
            var lockoutEnd = await _authService.GetLockoutEndAsync(user.Id);
            var failedAttempts = await _authService.GetFailedAttemptsAsync(user.Id);

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

            var result = await _authService.UnlockUserAsync(userId);

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
        /// Solicitar restablecimiento de contraseña
        /// </summary>
        [HttpPost("forgot-password")]
        public async Task<ActionResult<ApiResponse<string>>> ForgotPassword([FromBody] string email)
        {
            _logger.LogInformation("Solicitud de restablecimiento de contraseña para: {Email}", email);

            var result = await _authService.ForgotPassword(email);

            _logger.LogInformation("Enlace de restablecimiento enviado para: {Email}", email);

            return Ok(result);
        }

        /// <summary>
        /// Restablecer contraseña con token
        /// </summary>
        [HttpPost("reset-password")]
        public async Task<ActionResult<ApiResponse<string>>> ResetPassword([FromBody] ResetPassword request)
        {
            _logger.LogInformation("Restablecimiento de contraseña para: {Email}", request.Email);

            var result = await _authService.ResetPassword(request);

            _logger.LogInformation("Contraseña restablecida exitosamente para: {Email}", request.Email);

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

            var result = await _authService.UpdateUserAsync(userId, updateDto);

            _logger.LogInformation("Usuario {UserId} actualizado exitosamente", userId);

            return Ok(result);
        }

        /// <summary>
        /// Actualizar información básica del usuario
        /// </summary>
        [HttpPut("update")]
        [Authorize(Roles = "Admin")]
        public async Task<ActionResult<ApiResponse<object>>> UpdateUsers(string userId,[FromBody] UpdateUserDto updateDto)
        {
            
            _logger.LogInformation("Usuario {CurrentUserId} actualizando información de usuario {UserId}", userId, userId);

            var result = await _authService.UpdateUserAsync(userId, updateDto);

            _logger.LogInformation("Usuario {UserId} actualizado exitosamente", userId);

            return Ok(result);
        }
    }
}
