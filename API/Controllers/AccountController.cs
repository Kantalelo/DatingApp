using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    public class AccountController : BaseApiController
    {
        private readonly DataContext _Context;
      
        private readonly ITokenService _tokenService;

        public AccountController(DataContext context, ITokenService tokenService)
        {
            _tokenService = tokenService;
            _Context = context;

        }

        public object Get_tokenService()
        {
            return _tokenService;
        }

        [HttpPost("register")]
        public async Task<ActionResult<UserDto>> register( RegisterDto registerDto)
        {
            if (await UserExits(registerDto.Username)) return BadRequest("Username is taken");
            using var hmac = new HMACSHA512();

            var user = new AppUser
            {
                UserName = registerDto.Username.ToLower(),
                PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.password)),
                PasswordSalt = hmac.Key
            };

            _Context.Users.Add(user);
            await _Context.SaveChangesAsync();

            return new UserDto
            {
                Username = user.UserName,
                Token = _tokenService.CreateToken(user)
                
            };
           
           }

           [HttpPost("Login")]
           public async Task<ActionResult<UserDto>> Login(LoginDto loginDto)
           {
               var user = await _Context.Users.SingleOrDefaultAsync(x => x.UserName == loginDto.Username);

               if (user == null) return Unauthorized("Invalid username");

               using var hmac = new HMACSHA512(user.PasswordSalt);

               var ComputeHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));

               for (int i = 0; i<ComputeHash.Length; i++)
               {
                   if ( ComputeHash[i] != user.PasswordHash[i]) return Unauthorized("Password Invalid");
               }

               return new UserDto
            {
                Username = user.UserName,
                Token = _tokenService.CreateToken(user)
                
            };
           }

            private async Task<bool> UserExits(string username)
            {
                return await _Context.Users.AnyAsync(x => x.UserName == username.ToLower());

            }
        }

    
}