using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Input;
using WpfX.Security;

namespace WpfX.ViewModel
{
    public class MainViewModel
    {
        public MainViewModel()
        {
            SecureCommand = new SecureRelayCommand(MySecureMethod, x => true);
        }

        [Authorize(AuthorizationType.Allow, "SomeRole")]
        private static void MySecureMethod(object obj)
        {
            MessageBox.Show("You made it");
        }

        public ICommand SecureCommand { get; set; }
    }
}
