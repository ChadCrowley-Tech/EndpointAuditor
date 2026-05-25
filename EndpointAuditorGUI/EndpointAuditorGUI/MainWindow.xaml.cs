using System.Windows;
using System.Windows.Controls.Primitives;
using System.Windows.Media;

namespace EndpointAuditorGUI
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private void BtnRunAudit_Click(object sender, RoutedEventArgs e)
        {
            // Change button text while running
            btnRunAudit.Content = "SCANNING...";
            int secureCount = 0;

            // Define binary colors
            Brush colorSecure = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#10B981")); // Emerald Green
            Brush colorVulnerable = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#EF4444")); // Red

            // Check 1: Windows Defender
            if (SecurityAuditor.IsDefenderActive())
            {
                statusDefender.Text = "SECURE";
                statusDefender.Foreground = colorSecure;
                secureCount++;
            }
            else
            {
                statusDefender.Text = "VULNERABLE";
                statusDefender.Foreground = colorVulnerable;
            }

            // Check 2: Firewall Profiles
            if (SecurityAuditor.AreFirewallsActive())
            {
                statusFirewall.Text = "SECURE";
                statusFirewall.Foreground = colorSecure;
                secureCount++;
            }
            else
            {
                statusFirewall.Text = "VULNERABLE";
                statusFirewall.Foreground = colorVulnerable;
            }

            // Check 3: UAC
            if (SecurityAuditor.IsUACEnabled())
            {
                statusUAC.Text = "SECURE";
                statusUAC.Foreground = colorSecure;
                secureCount++;
            }
            else
            {
                statusUAC.Text = "VULNERABLE";
                statusUAC.Foreground = colorVulnerable;
            }

            // Check 4: SMBv1
            if (SecurityAuditor.IsSMBv1Disabled())
            {
                statusSMB.Text = "SECURE";
                statusSMB.Foreground = colorSecure;
                secureCount++;
            }
            else
            {
                statusSMB.Text = "VULNERABLE";
                statusSMB.Foreground = colorVulnerable;
            }

            // Check 5: Guest Account
            if (SecurityAuditor.IsGuestDisabled())
            {
                statusGuest.Text = "SECURE";
                statusGuest.Foreground = colorSecure;
                secureCount++;
            }
            else
            {
                statusGuest.Text = "VULNERABLE";
                statusGuest.Foreground = colorVulnerable;
            }

            // UPDATE OVERALL POSTURE
            txtScore.Text = $"{secureCount}/5";

            if (secureCount == 5)
            {
                txtOverallStatus.Text = "SECURE";
                txtOverallStatus.Foreground = colorSecure;
            }
            else
            {
                txtOverallStatus.Text = "AT RISK";
                txtOverallStatus.Foreground = colorVulnerable;
            }

            // Reset button text
            btnRunAudit.Content = "RE-SCAN";
        }
    }
}