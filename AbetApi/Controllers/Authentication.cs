﻿using Microsoft.AspNetCore.Mvc;
using System;
using System.Web;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using AbetApi.Authentication;
using System.Text;
using Microsoft.AspNetCore.Http;

namespace AbetApi.Controllers
{
    public class Authentication : ControllerBase
    {
        private readonly ILdap ldap;
        private readonly ITokenGenerator tokenGenerator;
        public Authentication(ILdap ldap, ITokenGenerator tokenGenerator)
        {
            this.ldap = ldap;
            this.tokenGenerator = tokenGenerator;
        }

        // This function is used to return a token that contains all of the roles a user has after successfully logging in
        [HttpPost("Login")]
        public ActionResult Login(string EUID, string encryptedPassword)
        {
            if (string.IsNullOrEmpty(EUID) || string.IsNullOrEmpty(encryptedPassword))
                return BadRequest();

            //A list used to store all of the roles given to the user logging in
            List<string> rolesToAdd = new List<string>();

            //This is a login Bypass for user credentials //////////////////////////////////////////
            //For user, type the role in all lowercase
            //For password, just type something. It could be anything.
            //This code only works when
            if (System.Diagnostics.Debugger.IsAttached)
            {
                switch (EUID)
                {
                    case "admin":
                        rolesToAdd.Add("Admin");
                        break;
                    case "instructor":
                        rolesToAdd.Add("Instructor");
                        break;
                    case "coordinator":
                        rolesToAdd.Add("Coordinator");
                        break;
                    case "student":
                        rolesToAdd.Add("Student");
                        break;
                }
            }
            if (rolesToAdd.Count > 0)
                return Ok(new { token = tokenGenerator.GenerateToken(EUID, rolesToAdd) });
            ///////////////////////////////////////////////////////////////////////////////////////////////////

            System.Diagnostics.Debug.WriteLine("EUID: " + EUID);
            System.Diagnostics.Debug.WriteLine("Password: " + encryptedPassword);

            //byte[] encryptedPasswordBytes = Convert.FromBase64String(HttpUtility.UrlDecode(encryptedPassword));
            byte[] encryptedPasswordBytes = Encoding.ASCII.GetBytes(Base64UrlEncoder.Decode(encryptedPassword));
            var cipher = new Security.AES(encryptedPassword); // create a new cipher object to handle decryption
            string password = cipher.Decrypt(encryptedPasswordBytes); // decrypt the password using the cipher

            System.Diagnostics.Debug.WriteLine("Password: " + password);

            //Validates user/password combo with UNT domain controller
            ldap.ValidateCredentials(EUID, password);

            //If the login worked, get all of the roles that user has, build a token, and return the token
            if (ldap.LoginSuccessful && !ldap.InternalErrorOccurred)
            {
                try
                {
                    var roles = EFModels.User.GetRolesByUser(EUID).Result;

                    //All users are at least a student
                    if (roles == null || roles.Count == 0)
                    {
                        rolesToAdd.Add("Student");
                    }
                    else if (roles.Count > 0)
                    {
                        foreach (EFModels.Role itr in roles)
                        {
                            rolesToAdd.Add(itr.Name);
                        }
                    }

                    string token = tokenGenerator.GenerateToken(EUID, rolesToAdd);

                    return Ok(new { token }); //user is logged in
                }
                catch(Exception ex)
                {
                    return BadRequest(ex.Message);
                }
            }
            //If their credentials are incorrect, send an error
            else if (!ldap.LoginSuccessful && !ldap.InternalErrorOccurred) // login was unsuccessful and the server did NOT encounter an error
                return BadRequest(new { message = ldap.ErrorMessage });
            //If this endpoint breaks for any other reason
            else
                return StatusCode(500, new { message = ldap.ErrorMessage }); //internal server error (500 error)
        }
    }
}
