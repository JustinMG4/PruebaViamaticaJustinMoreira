namespace PruebaViamaticaJustinMoreira.DTOs
{
    public class SessionStatsDto
    {
        public int ActiveSessions { get; set; }
        public int InactiveSessions { get; set; }
        public int LockedUsers { get; set; }
        public int TotalSessions { get; set; }
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    }
}
