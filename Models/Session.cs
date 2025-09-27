namespace PruebaViamaticaJustinMoreira.Models
{
    public class Session
    {
        public int SessionId { get; set; }
        public string UserId { get; set; }
        public DateTime StartDate { get; set; }
        public DateTime? LogoutDate { get; set; }
        public int Intents { get; set; }
        public bool IsActive => LogoutDate == null;

        // Relación
        public virtual User User { get; set; }
    }
}
