namespace PruebaViamaticaJustinMoreira.DTOs
{
    public class UserSessionStats
    {
        public int SessionId {get; set;}
        public DateTime? StartDate { get; set; }
        public DateTime? LogoutDate { get; set; }
        public int Intents { get; set; }
    }
}
