namespace PruebaViamaticaJustinMoreira.DTOs
{
    public class BulkRegisterResultDto
    {
        public int SuccessfulRegisters { get; set; }
        public int FailedRegisters { get; set; }
        public List<string> Errors { get; set; } = new List<string>();
    }
}
