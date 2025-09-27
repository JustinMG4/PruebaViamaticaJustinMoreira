using Microsoft.AspNetCore.Identity;
using PruebaViamaticaJustinMoreira.DTOs;
using PruebaViamaticaJustinMoreira.Models;

namespace PruebaViamaticaJustinMoreira.Interfaces
{
    public interface IAccountService
    {
        Task<IdentityResult> RegisterAsync(RegisterDto registerDto, string role);
        Task<string> LoginAsync(LoginDto loginDto);
        Task<bool> LogoutAsync(string userId);
        Task<User> GetUserByIdAsync(string userId);
        Task<Person> GetPersonByUserIdAsync(string userId);
        Task<bool> IsUserLockedOutAsync(string userId);
        Task<User> GetUserByEmailAsync(string email);
        Task<DateTimeOffset?> GetLockoutEndAsync(string userId);
        Task<int> GetFailedAttemptsAsync(string userId);
        Task<bool> UnlockUserAsync(string userId);
        Task<ApiResponse<string>> ResetPassword(ResetPassword request);
        Task<ApiResponse<string>> ForgotPassword(ForgotPasswordDto dto);
        Task<ApiResponse<object>> UpdateUserAsync(string userId, UpdateUserDto updateDto);
        Task<bool> LockedAccountAsync(string userId, int minutes);
        Task<BulkRegisterResultDto> RegisterBulkAsync(List<RegisterDto> usersToRegister, string role);
    }
}
