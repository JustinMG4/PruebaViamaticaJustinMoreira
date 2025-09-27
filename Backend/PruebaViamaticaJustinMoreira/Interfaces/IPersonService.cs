using PruebaViamaticaJustinMoreira.DTOs;

namespace PruebaViamaticaJustinMoreira.Interfaces
{
    public interface IPersonService
    {
        Task<List<PersonsDto>> GetAllPersonsAsync();

        Task<PersonsDto> GetPersonByIdAsync(string id);
    }
}
