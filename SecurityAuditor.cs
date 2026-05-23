
using System;
using Microsoft.Win32;

namespace EndpointAuditor
{
    public class SecurityAuditor
    {
        // Check 1: Verifies Windows Defender Real-Time Protection is active using PowerShell
        public static bool IsDefenderActive()
        {
            try
            {
                System.Diagnostics.Process process = new System.Diagnostics.Process();
                process.StartInfo.FileName = "powershell";
                // Get-MpPreference returns the Defender configuration. We want the DisableRealtimeMonitoring property.
                process.StartInfo.Arguments = "-Command \"(Get-MpPreference).DisableRealtimeMonitoring\"";
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.CreateNoWindow = true; // Prevents the PowerShell window from flashing
                process.Start();

                string output = process.StandardOutput.ReadToEnd().Trim();
                process.WaitForExit();

                // If DisableRealtimeMonitoring is 'False', then protection is ON
                if (output.Equals("False", StringComparison.OrdinalIgnoreCase))
                {
                    return true; // System is secure
                }

                return false; // Vulnerable or key is missing
            
            }

            catch (UnauthorizedAccessException)
            {
                return false;
            }
        }

        // Check 2: Verifies Domain, Private, and Public firewalls are all active
        public static bool AreFirewallsActive()
        {
            try
            {
                string basePath = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy";
                string[] profiles = { "DomainProfile", "StandardProfile", "PublicProfile" };

                foreach (string profile in profiles)
                {
                    // Check each profile one by one
                    using (RegistryKey key = Registry.LocalMachine.OpenSubKey($@"{basePath}\{profile}"))
                    {
                        if (key != null)
                        {
                            object value = key.GetValue("EnableFirewall");
                            // If any firewall profile is set to 0 (disabled), the whole check fails
                            if (value == null || (int)value == 0)
                            {
                                return false;
                            }
                        }
                        else
                        {
                            return false; // Key missing entirely
                        }
                    }
                }
                return true; // All three profiles returned a 1 (Active)
            }
            catch (UnauthorizedAccessException)
            {
                return false;
            }
        }

        // Check 3: Verifies User Account Control (UAC) is enabled
        public static bool IsUACEnabled()
        {
            try
            {
                string keyPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(keyPath))
                {
                    if (key != null)
                    {
                        object enableLUA = key.GetValue("EnableLUA");
                        object consentPrompt = key.GetValue("ConsentPromptBehaviorAdmin");
                        
                        // Check if the core UAC engine is on, 1 means on, 0 means disabled
                        if (enableLUA != null && (int)enableLUA == 1)
                        {
                            // Check if slider is set to notify user 
                            // 0 means 'Never Notify' and therefore vulnerable
                            if (consentPrompt != null && (int)consentPrompt > 0)
                            {
                                // Engine is on AND it will prompt the user 
                                return true;
                            }
                        }
                    }
                }
                return false;
            }
            catch (UnauthorizedAccessException)
            {
                return false;
            }
        }

        // Check 4: Verifies legacy SMBv1 Server protocol is disabled 
        public static bool IsSMBv1Disabled()
        {
            try
            {
                System.Diagnostics.Process process = new System.Diagnostics.Process();
                process.StartInfo.FileName = "powershell";
                // Checks the installation state of the legacy SMB1 feature
                process.StartInfo.Arguments = "-Command \"(Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol-Server).State\"";
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.CreateNoWindow = true; // Hides the console
                process.Start();

                string output = process.StandardOutput.ReadToEnd().Trim();
                process.WaitForExit();

                // If Server component is 'Disabled', the system is secure against SMBv1 exploits
                if (output.Equals("Disabled", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }

                return false; // Returns Vulnerable if 'Enabled'
            }
            catch
            {
                return false;
            }
        }

        // Check 5: Verifies the built-in Guest account is disabled
        public static bool IsGuestDisabled()
        {
            try
            {
                // The SAM registry is locked to SYSTEM level, so we run 'net user' instead
                System.Diagnostics.Process process = new System.Diagnostics.Process();
                process.StartInfo.FileName = "net";
                process.StartInfo.Arguments = "user guest";
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.CreateNoWindow = true; // Prevents the black console from flashing
                process.Start();

                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                // Removing spaces makes the check accurate even with different spacing
                if (output.Replace(" ", "").Contains("AccountactiveNo"))
                {
                    return true;
                }
                return false;
            }
            catch
            {
                return false;
            }
        }
    }
}
