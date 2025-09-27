namespace PruebaViamaticaJustinMoreira.DTOs
{
    public class UserFailedAttemptsDto
    {
        public string UserId { get; set; }
        public string UserName { get; set; }
        public string Email { get; set; }
        public string FullName { get; set; }
        public int AccessFailedCount { get; set; }

    }
}
