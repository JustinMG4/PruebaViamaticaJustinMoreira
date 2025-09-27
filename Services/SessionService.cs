using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using PruebaViamaticaJustinMoreira.Data;
using PruebaViamaticaJustinMoreira.DTOs;
using PruebaViamaticaJustinMoreira.Interfaces;
using PruebaViamaticaJustinMoreira.Models;
using PruebaViamaticaJustinMoreira.Exceptions;

namespace PruebaViamaticaJustinMoreira.Services
{
    public class SessionService : ISessionService
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<User> _userManager;

        public SessionService(ApplicationDbContext context, UserManager<User> userManager)
        {
            _context = context;
            _userManager = userManager;
        }

        public async Task<SessionStatsDto> GetSessionStatisticsAsync()
        {
            // Obtener la sesión más reciente por cada usuario
            var latestSessionsPerUser = await _context.Sessions
                .GroupBy(s => s.UserId)
                .Select(g => g.OrderByDescending(s => s.StartDate).First())
                .ToListAsync();

            // Contar sesiones activas e inactivas basándose en la sesión más reciente de cada usuario
            var activeSessions = latestSessionsPerUser.Count(s => s.LogoutDate == null);
            var inactiveSessions = latestSessionsPerUser.Count(s => s.LogoutDate != null);

            // Obtener usuarios bloqueados
            var allUsers = await _userManager.Users.ToListAsync();
            var lockedUsersCount = 0;

            foreach (var user in allUsers)
            {
                if (await _userManager.IsLockedOutAsync(user))
                {
                    lockedUsersCount++;
                }
            }

            return new SessionStatsDto
            {
                ActiveSessions = activeSessions,
                InactiveSessions = inactiveSessions,
                LockedUsers = lockedUsersCount,
                TotalSessions = activeSessions + inactiveSessions
            };
        }

        public async Task<UserSessionStats> GetLastActiveSessionAsync(string userId)
        {
            if (string.IsNullOrWhiteSpace(userId))
                throw new ValidationException("El identificador de usuario es requerido.");

            // Buscar la sesión más reciente del usuario que tenga tanto StartDate como LogoutDate
            var lastActiveSession = await _context.Sessions
                .Where(s => s.UserId == userId && s.LogoutDate != null)
                .OrderByDescending(s => s.StartDate)
                .FirstOrDefaultAsync();

            if (lastActiveSession==null)
                throw new NotFoundException("No se encontró ninguna sesión activa para el usuario especificado.");

            return new UserSessionStats
            {
                SessionId = lastActiveSession.SessionId,
                StartDate = lastActiveSession.StartDate,
                LogoutDate = lastActiveSession.LogoutDate,
                Intents = lastActiveSession.Intents
            };
        }

        public async Task<List<UserFailedAttemptsDto>> GetUsersWithFailedAttemptsAsync()
        {
            // Obtener usuarios con intentos fallidos directamente usando EF Core
            var usersWithFailedAttempts = await _context.Users
                .Where(u => u.AccessFailedCount > 0)
                .Include(u => u.Persons)
                .Select(u => new UserFailedAttemptsDto
                {
                    UserId = u.Id,
                    UserName = u.UserName,
                    Email = u.Email,
                    AccessFailedCount = u.AccessFailedCount,
                    FullName = u.Persons.Any()
                        ? u.Persons.First().Name + " " + u.Persons.First().LastName
                        : "Sin información personal"
                })
                .OrderByDescending(u => u.AccessFailedCount)
                .ToListAsync();

            return usersWithFailedAttempts;
        }
    }
}
