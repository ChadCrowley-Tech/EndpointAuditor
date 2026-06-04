using System;
using Microsoft.Win32;
using System.Windows;

namespace EndpointAuditorGUI
{
    public partial class SplashScreen : Window
    {
        public SplashScreen()
        {
            InitializeComponent();
        }

        private void BtnGetStarted_Click(object sender, RoutedEventArgs e)
        {
            // 1. Create a new instance of our main dashboard
            MainWindow dashboard = new MainWindow();

            // 2. Show the dashboard on the screen
            dashboard.Show();

            // 3. Close this splash screen so it doesn't linger in the background
            this.Close();
        }
    }
}
