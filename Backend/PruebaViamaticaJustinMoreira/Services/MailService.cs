using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
using MimeKit.Text;
using PruebaViamaticaJustinMoreira.DTOs;


namespace PruebaViamaticaJustinMoreira.Services
{
    public class MailService
    {
        private static string _Host = "smtp.gmail.com";
        private static int _Puerto = 587;

        private static string _NombreEnvia = "Plataforma de Prueba";
        private static string _Correo = "devjustinapps@gmail.com";
        private static string _Clave = "qtkfaxyakzzptdhh";

        public static bool Send(MailDto dto)
        {
            try
            {
                var email = new MimeMessage();

                email.From.Add(new MailboxAddress(_NombreEnvia, _Correo));
                email.To.Add(MailboxAddress.Parse(dto.To));
                email.Subject = dto.Subject;
                email.Body = new TextPart(TextFormat.Html)
                {
                    Text = dto.Content
                };

                using (var smtp = new SmtpClient())
                {
                    smtp.Connect(_Host, _Puerto, SecureSocketOptions.StartTls);

                    smtp.Authenticate(_Correo, _Clave);
                    smtp.Send(email);
                    smtp.Disconnect(true);
                }

                return true;
            }
            catch (SmtpCommandException ex)
            {
                Console.WriteLine($"Error SMTP Command: {ex.Message}");
                Console.WriteLine($"StatusCode: {ex.StatusCode}");
                return false;
            }
            catch (SmtpProtocolException ex)
            {
                Console.WriteLine($"Error de protocolo SMTP: {ex.Message}");
                return false;
            }
            catch (System.Security.Authentication.AuthenticationException ex)
            {
                Console.WriteLine($"Error de autenticación SMTP: {ex.Message}");
                return false;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error general al enviar el correo: {ex.Message}");
                return false;
            }
        }


        public static string GenerarToken()
        {
            string token = Guid.NewGuid().ToString("N");
            return token;
        }

    }
}
