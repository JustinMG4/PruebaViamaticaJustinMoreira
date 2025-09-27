using Microsoft.EntityFrameworkCore;
using PruebaViamaticaJustinMoreira.Data;
using PruebaViamaticaJustinMoreira.DTOs;
using PruebaViamaticaJustinMoreira.Interfaces;

namespace PruebaViamaticaJustinMoreira.Services
{
    public class PersonService : IPersonService
    {
        private readonly ApplicationDbContext _context;

        public PersonService(ApplicationDbContext context)
        {
            _context = context;
        }

        public async Task<List<PersonsDto>> GetAllPersonsAsync()
        {
            var persons = await _context.Persons
                .Include(p => p.User)
                .Select(p => new PersonsDto
                {
                    Id = p.UserId,
                    FirstName = p.Name,
                    LastName = p.LastName,
                    PersonalMail = p.User.Email,
                    PlatformMail = p.PlatformMail,
                    Identification = p.Identification,
                    BirthDate = p.BirthDate,
                    CreatedAt = p.User.DateOfRegister,
                    UserName = p.User.UserName,
                    Email = p.User.Email
                })
                .ToListAsync();

            return persons;
        }

        public async Task<PersonsDto> GetPersonByIdAsync(string userId)
        {
            var person = await _context.Persons
                .Include(p => p.User)
                .Where(p => p.UserId == userId)
                .Select(p => new PersonsDto
                {
                    Id = p.UserId,
                    FirstName = p.Name,
                    LastName = p.LastName,
                    PersonalMail = p.User.Email,
                    PlatformMail = p.PlatformMail,
                    Identification = p.Identification,
                    BirthDate = p.BirthDate,
                    CreatedAt = p.User.DateOfRegister,
                    UserName = p.User.UserName,
                    Email = p.User.Email
                })
                .FirstOrDefaultAsync();

            if (person == null)
            {
                throw new KeyNotFoundException("Persona no encontrada.");
            }
            return person;
        }
    }
}
