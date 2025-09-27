namespace PruebaViamaticaJustinMoreira.DTOs
{
    public class SessionHistoryDto
    {
        public int SessionId { get; set; }
        public DateTime StartDate { get; set; }
        public DateTime? LogoutDate { get; set; }
        public int Intents { get; set; }
        public TimeSpan? SessionDuration => LogoutDate.HasValue ? LogoutDate.Value - StartDate : null;
        public bool IsActive => LogoutDate == null;
        public string Status => IsActive ? "Activa" : "Finalizada";

    }
}
