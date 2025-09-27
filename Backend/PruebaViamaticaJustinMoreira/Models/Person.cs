namespace PruebaViamaticaJustinMoreira.Models
{
    public class Person
    {
        public int PersonId { get; set; }
        public string IdPerson { get; set; }
        public string Name { get; set; }
        public string LastName { get; set; }
        public string? PlatformMail { get; set; }
        public string Identification { get; set; }
        public DateTime BirthDate { get; set; }
        public string UserId { get; set; }

        // Relaciones
        public virtual User User { get; set; }
        public virtual ICollection<OptionsRoles> OptionsRoles { get; set; }
    }
}
