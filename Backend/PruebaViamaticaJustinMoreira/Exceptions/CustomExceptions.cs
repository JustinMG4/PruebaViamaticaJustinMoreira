namespace PruebaViamaticaJustinMoreira.Exceptions
{
    public class BusinessException : Exception
    {
        public BusinessException(string message) : base(message) { }
        public BusinessException(string message, Exception innerException) : base(message, innerException) { }
    }

    public class ValidationException : Exception
    {
        public List<string> Errors { get; }

        public ValidationException(string message) : base(message)
        {
            Errors = new List<string> { message };
        }

        public ValidationException(List<string> errors) : base("Errores de validación")
        {
            Errors = errors;
        }
    }

    public class UnauthorizedException : Exception
    {
        public UnauthorizedException(string message = "No autorizado") : base(message) { }
    }

    public class NotFoundException : Exception
    {
        public NotFoundException(string message = "Recurso no encontrado") : base(message) { }
    }                                                                                                           
}
