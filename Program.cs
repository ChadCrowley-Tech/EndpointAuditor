
using System;

namespace EndpointAuditor
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("========================================");
            Console.WriteLine("    ENDPOINT SECURITY AUDITOR v1.0      ");
            Console.WriteLine("========================================");
            Console.WriteLine("Initializing system scan...\n");

            // Check 1: Windows Defender
            Console.Write("[1] Checking Windows Defender Status... ");

            if (SecurityAuditor.IsDefenderActive())
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("SECURE (Active)");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("VULNERABLE (Disabled or Access Denied)");
            }

            Console.ResetColor();

            // Check 2: Firewall Profiles
            Console.Write("[2] Checking Windows Firewall Profiles... ");
            if (SecurityAuditor.AreFirewallsActive())
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("SECURE (All Profiles Active)");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("VULNERABLE (One or more profiles disabled)");
            }
            Console.ResetColor();

            // Check 3: User Account Control
            Console.Write("[3] Checking User Account Control (UAC)... ");
            if (SecurityAuditor.IsUACEnabled())
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("SECURE (Enabled)");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("VULNERABLE (Disabled)");
            }
            Console.ResetColor();

            // Check 4: Legacy SMBv1 Protocol
            Console.Write("[4] Checking SMBv1 Protocol Status... ");
            if (SecurityAuditor.IsSMBv1Disabled())
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("SECURE (Disabled)");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("VULNERABLE (Open)");
            }
            Console.ResetColor();

            // Check 5: Guest Account Status
            Console.Write("[5] Checking Built-in Guest Account... ");
            if (SecurityAuditor.IsGuestDisabled())
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("SECURE (Disabled)");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("VULNERABLE (Active)");
            }
            Console.ResetColor();

            Console.WriteLine("\nScan complete. Press any key to exit.");
            Console.ReadKey();
        }
    }
}
