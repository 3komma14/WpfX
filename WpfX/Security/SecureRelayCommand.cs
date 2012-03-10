using System;
using System.Security;
using System.Threading;
using System.Windows.Input;

namespace WpfX.Security
{
    public class SecureRelayCommand : ICommand
    {
        private readonly Action<object> _action;
        private readonly Func<object, bool> _canExecute;
        private readonly bool _isAuthorized;

        public SecureRelayCommand(Action<object> action, Func<object, bool> canExecute)
        {
            _action = action;
            _canExecute = canExecute;
            _isAuthorized = IsAuthorized(action);
        }

        private static bool IsAuthorized(Action<object> action)
        {
            var authorized = true;
            var attribs = action.Method.GetCustomAttributes(typeof(AuthorizeAttribute), true);
            if(attribs.Length == 0)
            {
                return true;
            }

            foreach (AuthorizeAttribute attrib in attribs)
            {
                switch (attrib.AuthorizationType)
                {
                    case AuthorizationType.Allow:
                        authorized = Thread.CurrentPrincipal.IsInRole(attrib.Role);
                        break;
                    case AuthorizationType.Deny:
                        authorized = !Thread.CurrentPrincipal.IsInRole(attrib.Role);
                        break;
                }
                if(authorized == false)
                {
                    break;
                }
            }
            return authorized;
        }

        public void Execute(object parameter)
        {
            if(!_isAuthorized)
            {
                throw new SecurityException("Not authorized to execute this method");                
            }
            if (CanExecute(parameter))
            {
                _action(parameter);
                return;
            }
        }

        public bool CanExecute(object parameter)
        {
            if(_isAuthorized)
            {
                return _canExecute != null ? _canExecute(parameter) : true;    
            }
            return false;
        }

        public event EventHandler CanExecuteChanged
        {
            add { CommandManager.RequerySuggested += value; }
            remove { CommandManager.RequerySuggested -= value;}
        }
    }
}
