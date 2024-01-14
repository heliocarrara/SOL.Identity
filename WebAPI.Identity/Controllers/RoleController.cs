using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using WebAPI.Domain;
using WebAPI.Identity.Dto;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace WebAPI.Identity.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class RoleController : ControllerBase
    {
        private readonly UserManager<User> _userManager;
        private readonly RoleManager<Role> _roleInManager;

        public RoleController(UserManager<User> userManager, RoleManager<Role> roleManager)
        {
            _roleInManager = roleManager;
            _userManager = userManager;
        }
        // GET: api/<RoleController>
        [HttpGet]
        [Authorize(Roles = "Admin")]
        public IActionResult Get()
        {
            return Ok(new { 
                role = new RoleDto(), 
                updateUserRole = new UpdateUserRoleDto()
            });
        }

        // GET api/<RoleController>/5
        [HttpGet("{id}", Name = "Get")]
        [Authorize(Roles = "Admin, Gerente")]
        public string Get(int id)
        {
            return "value";
        }

        // POST api/<RoleController>
        [HttpPost("CreateRole")]
        public async Task<IActionResult> CreateRole(RoleDto roleDto)
        {
            try
            {
                var retorno = await _roleInManager.CreateAsync(new Role { Name = roleDto.Name });

                return Ok(retorno);
            }
            catch (Exception ex)
            {
                return this.StatusCode(StatusCodes.Status500InternalServerError, $"Erro: {ex.Message}");
            }
        }

        // PUT api/<RoleController>/5
        [HttpPut("UpdateUserRole")]
        public async Task<IActionResult> UpdateUserRoles(UpdateUserRoleDto model)
        {
            try
            {
                var user = await _userManager.FindByEmailAsync(model.Email);

                if (user == null)
                {
                    return Ok("usuário não encontrado!");
                }

                if (model.Delete)
                {
                    await _userManager.RemoveFromRoleAsync(user, model.Role);
                }
                else
                {
                    await _userManager.AddToRoleAsync(user, model.Role);
                }

                return Ok("Sucesso!");
            }
            catch (Exception ex)
            {
                return this.StatusCode(StatusCodes.Status500InternalServerError, $"Erro: {ex.Message}");
            }
        }

        // DELETE api/<RoleController>/5
        [HttpDelete("{id}")]
        public void Delete(int id)
        {
        }
    }
}
