
using System;
using Microsoft.Win32;

namespace EndpointAuditorGUI
{
    /// <summary>
    /// The core auditing engine. Executes local system queries to verify endpoint compliance against 
    /// established enterprise security baselines.
    /// </summary>
    public class SecurityAuditor
    {
        // ===================================
        // PHASE 1: NETWORK LOGIC (3 Checks)
        // ===================================

        /// <summary>
        /// Check 1: Verifies Domain, Private, and Public firewalls are all active.
        /// Directly queries the registry to avoid slow WMI calls.
        /// </summary>
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

        /// <summary>
        /// Check 2: Verifies legacy SMBv1 Server protocol is disabled to prevent lateral movement attacks.
        /// </summary>
        public static bool IsSMBv1Disabled()
        {
            try
            {
                System.Diagnostics.Process process = new System.Diagnostics.Process();
                process.StartInfo.FileName = "powershell";
                // Checks the installation state of the SMB1 feature
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

        /// <summary>
        /// Check 3: Verifies LLMNR is disabled. Leaving this ON allows local network credential theft via poisoning.
        /// </summary>
        public static bool IsLLMNRDisabled()
        {
            try
            {
                string keyPath = @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient";
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(keyPath))
                {
                    if (key != null)
                    {
                        object value = key.GetValue("EnableMulticast");
                        // 0 means Multicast (LLMNR) is completely turned off
                        if (value != null && (int)value == 0)
                        {
                            return true;
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

        // =====================================
        // PHASE 2: EXECUTION LOGIC (4 Checks)
        // =====================================

        /// <summary>
        /// Check 4: Verifies Windows Defender Real-Time Protection is active.
        /// Uses hidden PowerShell processes to query the native Defender module.
        /// </summary>
        public static bool IsDefenderActive()
        {
            try
            {
                System.Diagnostics.Process process = new System.Diagnostics.Process();
                process.StartInfo.FileName = "powershell";
                process.StartInfo.Arguments = "-Command \"(Get-MpPreference).DisableRealtimeMonitoring\"";
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.CreateNoWindow = true; // Prevents the PowerShell window from flashing
                process.Start();

                string output = process.StandardOutput.ReadToEnd().Trim();
                process.WaitForExit();

                // If DisableRealtimeMonitoring is 'False', then protection is safely ON
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

        /// <summary>
        /// Check 5: Verifies the PowerShell Execution Policy restricts unauthorized scripts
        /// </summary>
        public static bool IsExecutionPolicySecure()
        {
            try
            {
                System.Diagnostics.Process process = new System.Diagnostics.Process();
                process.StartInfo.FileName = "powershell";
                process.StartInfo.Arguments = "-Command \"Get-ExecutionPolicy\"";
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.CreateNoWindow = true;
                process.Start();

                string output = process.StandardOutput.ReadToEnd().Trim();
                process.WaitForExit();

                // Restricts execution to authorized scripts only
                if (output.Equals("Restricted", StringComparison.OrdinalIgnoreCase) ||
                    output.Equals("RemoteSigned", StringComparison.OrdinalIgnoreCase) ||
                    output.Equals("AllSigned", StringComparison.OrdinalIgnoreCase))
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

        /// <summary>
        /// Check 6: Verifies PowerShell Script Block Logging is enabled for forensic auditing.
        /// </summary>
        public static bool IsScriptBlockLoggingEnabled()
        {
            try
            {
                string keyPath = @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging";
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(keyPath))
                {
                    if (key != null)
                    {
                        object value = key.GetValue("EnableScriptBlockLogging");
                        // 1 means logging is actively recording script contents
                        if (value != null && (int)value == 1)
                        {
                            return true;
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

        /// <summary>
        /// Check 7: Verifies malicious AutoRun on USB drives is disabled globally
        /// </summary>
        public static bool IsAutoRunDisabled()
        {
            try
            {
                string keyPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(keyPath))
                {
                    if (key != null)
                    {
                        object value = key.GetValue("NoDriveTypeAutoRun");
                        // 255 (0xFF) disables AutoRun across all drive types
                        if (value != null && (int)value == 255)
                        {
                            return true;
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

        // ===========================================
        // PHASE 3: iDENTITY & DATA LOGIC (3 Checks)
        // ===========================================

        /// <summary>
        /// Check 8: Verifies User Account Control (UAC) is enabled and set to notify.
        /// </summary>
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

        /// <summary>
        /// Check 9: Verifies the built-in Guest account is disabled
        /// </summary>
        public static bool IsGuestAccountDisabled()
        {
            try
            {
                // The SAM registry is locked to SYSTEM level, using 'net user' instead.
                System.Diagnostics.Process process = new System.Diagnostics.Process();
                process.StartInfo.FileName = "net";
                process.StartInfo.Arguments = "user guest";
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.CreateNoWindow = true; 
                process.Start();

                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();

                // Removing spaces to keep the check accurate even with different spacing
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
        
        /// <summary>
        /// Check 10: Verifies the primary C: Drive is encrypted via BitLocker.
        /// Implements Fail-Safe state checking to handle Home edition endpoints.
        /// </summary>
        public static bool? IsBitLockerActive()
        {
            try
            {
                // 1. OS Licensing Check using the internal Microsoft Edition IDs.
                string registryKey = @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion";
                string editionId = (string)Registry.GetValue(registryKey, "EditionID", "");

                // 'Core' or 'Home' indicates Windows Home editions where full BitLocker configuration is unavailable
                if (!string.IsNullOrEmpty(editionId) &&
                    (editionId.Contains("Core", StringComparison.OrdinalIgnoreCase) ||
                     editionId.Contains("Home", StringComparison.OrdinalIgnoreCase)))
                {
                    return null; // Short-circuit directly to UNSUPPORTED for Home endpoints
                }

                // 2. Proceed with standard PowerShell scan for Pro/Enterprise endpoints
                System.Diagnostics.Process process = new System.Diagnostics.Process();
                process.StartInfo.FileName = "powershell";
                process.StartInfo.Arguments = "-Command \"(Get-BitLockerVolume -MountPoint 'C:').ProtectionStatus\"";
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.RedirectStandardError = true;
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.CreateNoWindow = true;
                process.Start();

                string output = process.StandardOutput.ReadToEnd().Trim();
                string error = process.StandardError.ReadToEnd().Trim();
                process.WaitForExit();

                // Fallback catch for unexpected native WMI/COM exceptions.
                if (!string.IsNullOrEmpty(error) || string.IsNullOrEmpty(output))
                {
                    return null;
                }

                if (output.Equals("On", StringComparison.OrdinalIgnoreCase))
                {
                    return true; // Secure
                }

                if (output.Equals("Off", StringComparison.OrdinalIgnoreCase))
                {
                    return false; // Vulnerable (Confirmed present but disabled)
                }

                return null;
            }
            catch
            {
                return null;
            }
        }

    }
}
