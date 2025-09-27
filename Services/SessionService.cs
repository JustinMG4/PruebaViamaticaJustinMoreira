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
            var latestSessionsPerUser = await _context.Sessions
                .GroupBy(s => s.UserId)
                .Select(g => g.OrderByDescending(s => s.StartDate).First())
                .ToListAsync();

            var activeSessions = latestSessionsPerUser.Count(s => s.LogoutDate == null);
            var inactiveSessions = latestSessionsPerUser.Count(s => s.LogoutDate != null);

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

            var lastActiveSession = await _context.Sessions
                .Where(s => s.UserId == userId && s.LogoutDate != null)
                .OrderByDescending(s => s.StartDate)
                .FirstOrDefaultAsync();

            if (lastActiveSession == null)
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
            var users = await _context.Users
                .Include(u => u.Persons)
                .Where(u => u.AccessFailedCount > 0 || u.LockoutEnd != null)
                .ToListAsync();

            var result = new List<UserFailedAttemptsDto>();

            foreach (var user in users)
            {
                bool isLockedOut = await _userManager.IsLockedOutAsync(user);

                if (user.AccessFailedCount > 0 || isLockedOut)
                {
                    result.Add(new UserFailedAttemptsDto
                    {
                        UserId = user.Id,
                        UserName = user.UserName,
                        Email = user.Email,
                        AccessFailedCount = user.AccessFailedCount,
                        FullName = user.Persons.Any()
                            ? user.Persons.First().Name + " " + user.Persons.First().LastName
                            : "Sin información personal"
                    });
                }
            }

            return result.OrderByDescending(u => u.AccessFailedCount).ToList();
        }

        public async Task<List<SessionHistoryDto>> GetUserSessionHistoryAsync(string userId)
        {
            if (string.IsNullOrWhiteSpace(userId))
                throw new ValidationException("El identificador de usuario es requerido.");

            var userExists = await _userManager.FindByIdAsync(userId);
            if (userExists == null)
                throw new NotFoundException("Usuario no encontrado.");

            var sessionHistory = await _context.Sessions
                .Where(s => s.UserId == userId)
                .OrderByDescending(s => s.StartDate)
                .Select(s => new SessionHistoryDto
                {
                    SessionId = s.SessionId,
                    StartDate = s.StartDate,
                    LogoutDate = s.LogoutDate,
                    Intents = s.Intents
                })
                .ToListAsync();

            return sessionHistory;
        }
    }
}
