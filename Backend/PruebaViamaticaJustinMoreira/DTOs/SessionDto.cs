namespace PruebaViamaticaJustinMoreira.DTOs
{
    public class SessionDto
    {
        public int SessionId { get; set; }
        public DateTime StartDate { get; set; }
        public DateTime? LogoutDate { get; set; }
        public bool IsActive { get; set; }
    }
}
