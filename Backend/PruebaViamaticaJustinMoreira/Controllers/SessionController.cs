using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PruebaViamaticaJustinMoreira.DTOs;
using PruebaViamaticaJustinMoreira.Interfaces;
using PruebaViamaticaJustinMoreira.Models;
using PruebaViamaticaJustinMoreira.Services;
using System.Security.Claims;

namespace PruebaViamaticaJustinMoreira.Controllers
{
    [ApiController]
    [Route("api/[controller]")]

    public class SessionController : ControllerBase
    {
        private readonly ISessionService _sessionService;
        private readonly ILogger<SessionController> _logger;

        public SessionController(ISessionService sessionService, ILogger<SessionController> logger)
        {
            _sessionService = sessionService;
            _logger = logger;
        }

        /// <summary>
        /// Obtener estadísticas de sesiones y usuarios
        /// </summary>
        [HttpGet("statistics")]
        [Authorize(Roles = "Admin")]
        public async Task<ActionResult<ApiResponse<SessionStatsDto>>> GetSessionStatistics()
        {
            _logger.LogInformation("Consultando estadísticas de sesiones");

            var stats = await _sessionService.GetSessionStatisticsAsync();

            return Ok(ApiResponse<SessionStatsDto>.SuccessResponse(
                stats,
                "Estadísticas obtenidas exitosamente"
            ));
        }

        ///<summary>
        /// Obtener estadísticas de sesiones y usuarios
        /// </summary>
        [HttpGet("statistics-by-user")]
        [Authorize]
        public async Task<ActionResult<ApiResponse<UserSessionStats>>> GetSessionStatisticsByUser()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var lastSession = await _sessionService.GetLastActiveSessionAsync(userId);
            return Ok(ApiResponse<UserSessionStats>.SuccessResponse(
                lastSession,
                "Estadísticas obtenidas exitosamente"
            ));
        }

        /// <summary>
        /// Obtener usuarios con intentos fallidos basándose en AccessFailedCount
        /// </summary>
        [HttpGet("failed-attempts")]
        [Authorize(Roles = "Admin")]

        public async Task<ActionResult<ApiResponse<List<UserFailedAttemptsDto>>>> GetUsersWithFailedAttempts()
        {
            _logger.LogInformation("Consultando usuarios con intentos fallidos");

            var usersWithFailedAttempts = await _sessionService.GetUsersWithFailedAttemptsAsync();

            return Ok(ApiResponse<List<UserFailedAttemptsDto>>.SuccessResponse(
                usersWithFailedAttempts,
                $"Se encontraron {usersWithFailedAttempts.Count} usuarios con intentos fallidos"
            ));
        }

        /// <summary>
        /// Obtener el historial completo de sesiones de un usuario
        /// </summary>
        [HttpGet("history/{userId}")]
        [Authorize(Roles = "Admin")]
        public async Task<ActionResult<ApiResponse<List<SessionHistoryDto>>>> GetUserSessionHistory(string userId)
        {
            _logger.LogInformation("Consultando historial de sesiones para usuario: {UserId}", userId);

            var sessionHistory = await _sessionService.GetUserSessionHistoryAsync(userId);

            return Ok(ApiResponse<List<SessionHistoryDto>>.SuccessResponse(
                sessionHistory,
                $"Historial de sesiones obtenido exitosamente. Total: {sessionHistory.Count} sesiones"
            ));
        }

        /// <summary>
        /// Obtener el historial de sesiones del usuario actual
        /// </summary>
        [HttpGet("my-history")]
        [Authorize]
        public async Task<ActionResult<ApiResponse<List<SessionHistoryDto>>>> GetMySessionHistory()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            _logger.LogInformation("Consultando historial de sesiones para usuario actual: {UserId}", userId);

            var sessionHistory = await _sessionService.GetUserSessionHistoryAsync(userId);

            return Ok(ApiResponse<List<SessionHistoryDto>>.SuccessResponse(
                sessionHistory,
                $"Historial de sesiones obtenido exitosamente. Total: {sessionHistory.Count} sesiones"
            ));
        }
    }
}
