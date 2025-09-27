namespace PruebaViamaticaJustinMoreira.Models
{
    using Microsoft.AspNetCore.Identity;
    public class User : IdentityUser
    {
        public DateTime DateOfRegister { get; set; }

        public virtual ICollection<Session> Sessions { get; set; } = new List<Session>();
        public virtual ICollection<Person> Persons { get; set; } = new List<Person>();
    }
}
