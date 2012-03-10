using System.Security.Principal;
using System.Threading;
using NUnit.Framework;
using WpfX.Security;

namespace UnitTests
{
    [TestFixture]
    public class AuthorizationTests
    {
        private string LastMethodExeuted = string.Empty;


        [Test]
        public void CanExecute_AllowRoleSatisfied_ReturnsTrue()
        {
            // Arrange
            Thread.CurrentPrincipal = new GenericPrincipal(new GenericIdentity("SomeUser"), new string[] {"Role1"});
            var command = new SecureRelayCommand(AllowRoleMethod, x => true);

            // Act
            var result = command.CanExecute(null);

            // Assert
            Assert.IsTrue(result);
        }

        [Test]
        public void CanExecute_AllowRoleNotSatisfied_ReturnsFalse()
        {
            // Arrange
            Thread.CurrentPrincipal = new GenericPrincipal(new GenericIdentity("SomeUser"), new string[]{});
            var command = new SecureRelayCommand(AllowRoleMethod, x => true);

            // Act
            var result = command.CanExecute(null);

            // Assert
            Assert.IsFalse(result);
        }

        [Test]
        public void CanExecute_DenyRoleSatisfied_ReturnsTrue()
        {
            // Arrange
            Thread.CurrentPrincipal = new GenericPrincipal(new GenericIdentity("SomeUser"), new string[] {});
            var command = new SecureRelayCommand(DenyRoleMethod, x => true);

            // Act
            var result = command.CanExecute(null);

            // Assert
            Assert.IsTrue(result);
        }

        [Test]
        public void CanExecute_DenyRoleNotSatisfied_ReturnsFalse()
        {
            // Arrange
            Thread.CurrentPrincipal = new GenericPrincipal(new GenericIdentity("SomeUser"), new string[] { "Role1" });
            var command = new SecureRelayCommand(DenyRoleMethod, x => true);

            // Act
            var result = command.CanExecute(null);

            // Assert
            Assert.IsFalse(result);
        }

        [Test]
        public void CanExecute_IsAuthorized_ReturnsCanExecuteFunc()
        {
            // Arrange
            Thread.CurrentPrincipal = new GenericPrincipal(new GenericIdentity("SomeUser"), new string[] { "Role1" });
            var command = new SecureRelayCommand(AllowRoleMethod, x => false);

            // Act
            var result = command.CanExecute(null);

            // Assert
            Assert.IsFalse(result);
        }

        [Test]
        public void Execute_IsAuthorized_MethodIsExecuted()
        {
            // Arrange
            Thread.CurrentPrincipal = new GenericPrincipal(new GenericIdentity("SomeUser"), new string[] { "Role1" });
            var command = new SecureRelayCommand(AllowRoleMethod, x => true);

            // Act
            command.Execute(null);

            // Assert
            Assert.AreEqual("AllowRoleMethod", LastMethodExeuted);
        }



        [Authorize(AuthorizationType.Allow, "Role1")]
        private void AllowRoleMethod(object obj)
        {
            LastMethodExeuted = "AllowRoleMethod";
        }

        [Authorize(AuthorizationType.Deny, "Role1")]
        private void DenyRoleMethod(object obj)
        {
            LastMethodExeuted = "DenyRoleMethod";
        }
    }
}
