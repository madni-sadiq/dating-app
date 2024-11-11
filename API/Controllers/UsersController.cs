using System;
using API.Data;
using API.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace API.Controllers;

public class UsersController (DataContext context) : BaseApiController
{

    [AllowAnonymous]
    [HttpGet]
    public ActionResult<IEnumerable<AppUser>> GetUsers()
    {
        var users = context.Users.ToList();

        return users;

    }

    [Authorize]
    [HttpGet("{id}")]
    public ActionResult<AppUser> GetUser(int id)
    {
        var user = context.Users.Find(id);
        
        if (user == null) return NotFound();

        return user;

    }
}
