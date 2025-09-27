using PruebaViamaticaJustinMoreira.DTOs;
using PruebaViamaticaJustinMoreira.Models;

namespace PruebaViamaticaJustinMoreira.Interfaces
{
    public interface ISessionService
    {
        Task<SessionStatsDto> GetSessionStatisticsAsync();
        Task<UserSessionStats> GetLastActiveSessionAsync(string userId);
        Task<List<UserFailedAttemptsDto>> GetUsersWithFailedAttemptsAsync();
        Task<List<SessionHistoryDto>> GetUserSessionHistoryAsync(string userId);

    }
}
