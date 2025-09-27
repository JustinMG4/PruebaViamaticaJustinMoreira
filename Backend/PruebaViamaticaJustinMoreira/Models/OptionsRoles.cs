namespace PruebaViamaticaJustinMoreira.Models
{
    public class OptionsRoles
    {
        public int Id { get; set; }
        public string OptionName { get; set; }
        public int IdOption { get; set; }
        public int PersonId { get; set; }

        // Relación
        public Person Person { get; set; }
    }
}
