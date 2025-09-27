using PruebaViamaticaJustinMoreira.Exceptions;
using System.Net;
using System.Text.Json;

namespace PruebaViamaticaJustinMoreira.Middlewares
{
    public class ExceptionHandlingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<ExceptionHandlingMiddleware> _logger;

        public ExceptionHandlingMiddleware(RequestDelegate next, ILogger<ExceptionHandlingMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            try
            {
                await _next(context);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An unhandled exception occurred");
                await HandleExceptionAsync(context, ex);
            }
        }

        private static async Task HandleExceptionAsync(HttpContext context, Exception exception)
        {
            var response = context.Response;
            response.ContentType = "application/json";

            var apiResponse = exception switch
            {
                ValidationException validationEx => new
                {
                    Success = false,
                    Message = validationEx.Message,
                    Errors = validationEx.Errors,
                    Timestamp = DateTime.UtcNow
                },
                BusinessException businessEx => new
                {
                    Success = false,
                    Message = businessEx.Message,
                    Errors = new List<string>(),
                    Timestamp = DateTime.UtcNow
                },
                UnauthorizedException unauthorizedEx => new
                {
                    Success = false,
                    Message = unauthorizedEx.Message,
                    Errors = new List<string>(),
                    Timestamp = DateTime.UtcNow
                },
                NotFoundException notFoundEx => new
                {
                    Success = false,
                    Message = notFoundEx.Message,
                    Errors = new List<string>(),
                    Timestamp = DateTime.UtcNow
                },
                _ => new
                {
                    Success = false,
                    Message = "Error interno del servidor",
                    Errors = new List<string>(),
                    Timestamp = DateTime.UtcNow
                }
            };

            response.StatusCode = exception switch
            {
                ValidationException => (int)HttpStatusCode.BadRequest,
                BusinessException => (int)HttpStatusCode.BadRequest,
                UnauthorizedException => (int)HttpStatusCode.Unauthorized,
                NotFoundException => (int)HttpStatusCode.NotFound,
                _ => (int)HttpStatusCode.InternalServerError
            };

            var jsonResponse = JsonSerializer.Serialize(apiResponse, new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            });

            await response.WriteAsync(jsonResponse);
        }
    }
}
