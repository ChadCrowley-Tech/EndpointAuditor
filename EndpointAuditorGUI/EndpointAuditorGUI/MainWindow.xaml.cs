using System;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace EndpointAuditorGUI
{
    /// <summary>
    /// Main interaction logic for the EndpointAuditor Dashboard.
    /// Handles execution of security checks to prevent UI thread blocking.
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        /// <summary>
        /// Triggers the full suite of security audits.
        /// Uses Task.Run() to ensure the heavy backend PowerShell processes
        /// do not freeze or stutter the WPF rendersing thread
        /// </summary>
        private async void BtnRunAll_Click(object sender, RoutedEventArgs e)
        {
            // Lock the button during execution and provide visual feedback to fit the sidebar width
            BtnRunAll.IsEnabled = false;
            BtnRunAll.Content = "SCANNING...";

            // Execute all auditing domains
            await RunNetworkAuditsAsync();
            await RunExecutionAuditsAsync();
            await RunIdentityAndHardwareAuditsAsync();

            // Unlock and reset the button to its original state
            BtnRunAll.IsEnabled = true;
            BtnRunAll.Content = "START AUDIT";
        }
        /// <summary>
        /// Executes Phase 1: Network Vulnerability Checks
        /// </summary>
        private async Task RunNetworkAuditsAsync()
        {
            bool firewallSecure = await Task.Run(() => SecurityAuditor.AreFirewallsActive());
            UpdateResultText(TxtFirewall, firewallSecure, "SECURE (Profiles Active)", "VULNERABLE (Profiles Disabled)");

            bool smbv1Secure = await Task.Run(() => SecurityAuditor.IsSMBv1Disabled());
            UpdateResultText(TxtSMBv1, smbv1Secure, "SECURE (Disabled)", "VULNERABLE (SMBv1 Active)");

            bool llmnrSecure = await Task.Run(() => SecurityAuditor.IsLLMNRDisabled());
            UpdateResultText(TxtLLMNR, llmnrSecure, "SECURE (Disabled)", "VULNERABLE (Multicast Active)");
        }
        /// <summary>
        /// Executes Phase 2: Execution and Scripting Checks
        /// </summary>
        private async Task RunExecutionAuditsAsync()
        {
            bool defenderSecure = await Task.Run(() => SecurityAuditor.IsDefenderActive());
            UpdateResultText(TxtDefender, defenderSecure, "SECURE (Active)", "VULNERABLE (Disabled or Tampered)");

            bool execPolicySecure = await Task.Run(() => SecurityAuditor.IsExecutionPolicySecure());
            UpdateResultText(TxtExecPolicy, execPolicySecure, "SECURE (Restricted)", "VULNERABLE (Unrestricted)");

            bool scriptLoggingSecure = await Task.Run(() => SecurityAuditor.IsScriptBlockLoggingEnabled());
            UpdateResultText(TxtScriptLogging, scriptLoggingSecure, "SECURE (Enabled)", "VULNERABLE (Disabled)");

            bool autoRunSecure = await Task.Run(() => SecurityAuditor.IsAutoRunDisabled());
            UpdateResultText(TxtAutoRun, autoRunSecure, "SECURE (Disabled)", "VULNERABLE (Active)");
        }
        /// <summary>
        /// Executes Phase 3: Identity and Hardware Encrytion Checks
        /// </summary>
        private async Task RunIdentityAndHardwareAuditsAsync()
        {
            bool uacSecure = await Task.Run(() => SecurityAuditor.IsUACEnabled());
            UpdateResultText(TxtUAC, uacSecure, "SECURE (LUA Enabled)", "VULNERABLE (LUA Disabled)");

            bool guestSecure = await Task.Run(() => SecurityAuditor.IsGuestAccountDisabled());
            UpdateResultText(TxtGuest, guestSecure, "SECURE (Disabled)", "VULNERABLE (Active)");
            
            // BitLocker returns a nullable boolean to accoumt for OS feature limitations
            bool? bitLockerSecure = await Task.Run(() => SecurityAuditor.IsBitLockerActive());
            UpdateNullableResultText(TxtBitLocker, bitLockerSecure, "SECURE (Encrypted)", "VULNERABLE (Unencrypted)", "UNSUPPORTED (OS Limitation)");
        }
        /// <summary>
        /// Helper function to update UI text properties based on standard binary security checks.
        /// </summary>
        private void UpdateResultText(TextBlock textBlock, bool isSecure, string secureMessage, string vulnMessage)
        {
            // Hex colors matching the Acid Green and Danger Red from the App.xaml palette
            if (isSecure)
            {
                textBlock.Text = secureMessage;
                textBlock.Foreground = (SolidColorBrush)new BrushConverter().ConvertFrom("#39FF14");
            }
            else
            {
                textBlock.Text = vulnMessage;
                textBlock.Foreground = (SolidColorBrush)new BrushConverter().ConvertFrom("#FF3366");
            }
        }

        /// <summary>
        /// Helper function for 3-state (Nullable) checks where features might be unsupported by the OS.
        /// </summary>
        private void UpdateNullableResultText(TextBlock textBlock, bool? isSecure, string secureMessage, string vulnMessage, string unsuppMessage)
        {
            if (isSecure == true)
            {
                textBlock.Text = secureMessage;
                textBlock.Foreground = (SolidColorBrush)new BrushConverter().ConvertFrom("#39FF14"); // Acid Green
            }
            else if (isSecure == false)
            {
                textBlock.Text = vulnMessage;
                textBlock.Foreground = (SolidColorBrush)new BrushConverter().ConvertFrom("#FF3366"); // Danger Red
            }
            else // It is strictly null, meaning the check is not applicable.
            {
                textBlock.Text = unsuppMessage;
                textBlock.Foreground = (SolidColorBrush)new BrushConverter().ConvertFrom("#A09DB0"); // Neutral Secondary Grey
            }
        }
    }
}