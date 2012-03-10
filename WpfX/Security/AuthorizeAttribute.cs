using System;

namespace WpfX.Security
{
    [AttributeUsage(AttributeTargets.Method, AllowMultiple = true)]
    public class AuthorizeAttribute : Attribute
    {
        public AuthorizationType AuthorizationType { get; private set; }
        public string Role { get; private set; }

        public AuthorizeAttribute(AuthorizationType authorizationType, string role)
        {
            AuthorizationType = authorizationType;
            Role = role;
        }
    }
}