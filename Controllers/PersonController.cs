using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PruebaViamaticaJustinMoreira.DTOs;
using PruebaViamaticaJustinMoreira.Interfaces;
using PruebaViamaticaJustinMoreira.Models;

namespace PruebaViamaticaJustinMoreira.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize(Roles = "Admin")] 
    public class PersonController : ControllerBase
    {
        private readonly IPersonService _personService;
        private readonly ILogger<PersonController> _logger;

        public PersonController(IPersonService personService, ILogger<PersonController> logger)
        {
            _personService = personService;
            _logger = logger;
        }

        /// <summary>
        /// Obtener todas las personas con su información de usuario
        /// </summary>
        [HttpGet("all")]
        public async Task<ActionResult<ApiResponse<List<PersonsDto>>>> GetAllPersons()
        {
            _logger.LogInformation("Consultando todas las personas");

            var persons = await _personService.GetAllPersonsAsync();

            return Ok(ApiResponse<List<PersonsDto>>.SuccessResponse(
                persons,
                $"Se encontraron {persons.Count} personas"
            ));
        }

        [HttpGet("person/{id}")]
        public async Task<ActionResult<ApiResponse<PersonsDto>>> GetPersonById(string id)
        {
            _logger.LogInformation($"Consultando persona con ID: {id}");
            var person = await _personService.GetPersonByIdAsync(id);
            return Ok(ApiResponse<PersonsDto>.SuccessResponse(
                person,
                "Persona encontrada"
            ));
        }
    }
}
