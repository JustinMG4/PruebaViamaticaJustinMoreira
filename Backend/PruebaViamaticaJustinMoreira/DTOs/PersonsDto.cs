namespace PruebaViamaticaJustinMoreira.DTOs
{
    public class PersonsDto
    {
        public string Id { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string PersonalMail { get; set; }
        public string? PlatformMail { get; set; }
        public string Identification { get; set; }
        public DateTime BirthDate { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public string UserName { get; set; }
        public string Email { get; set; }
    }
}
