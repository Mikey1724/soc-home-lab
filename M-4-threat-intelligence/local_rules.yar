import "pe" // analysis of Windows executables (imports, sections, resources)

rule Lumma_Stealer_C2_Pattern {
    meta:
        author      = "Mik"
        date        = "2026-09"
        description = "Detects Lumma Stealer C2 communication pattern"
        reference   = "SOC Home Lab - Month 1 PCAP Analysis (2026-01-31)"
        tlp         = "TLP:WHITE"
        mitre       = "T1071.001, T1555.003"

    strings:
        // C2 URI pattern from PCAP analysis
        $c2_uri     = "/api/set_agent" ascii nocase
        // Token parameter structure
        $c2_param   = "act=log" ascii nocase
        // Agent parameter for browser credential theft
        $agent_chrome = "agent=Chrome" ascii nocase
        $agent_edge   = "agent=Edge" ascii nocase
        // Lumma Stealer User-Agent pattern
        $ua = "Mozilla/5.0" ascii

    condition:
        $c2_uri and
        ($c2_param or $agent_chrome or $agent_edge) and
        $ua
}

rule NetSupport_RAT_C2 {
    meta:
        author      = "Mik"
        date        = "2026-09"
        description = "Detects NetSupport RAT C2 communication pattern"
        reference   = "SOC Home Lab - Month 1 PCAP Analysis (2026-02-28)"
        tlp         = "TLP:WHITE"
        mitre       = "T1219, T1071.001"

    strings:
        // Known C2 URI from NetSupport RAT
        $c2_uri     = "/fakeurl.htm" ascii nocase
        // NetSupport Manager User-Agent signature
        $ua         = "NetSupport Manager" ascii
        // Server response banner
        $server     = "NetSupport Gateway" ascii

    condition:
        $c2_uri and ($ua or $server)
}

rule Suspicious_PE_Strings_v2
{
    meta:
        author      = "Mik"
        date        = "2026-09"
        description = "Detects suspicious PE behavior: credential theft, HTTP C2, obfuscated PowerShell, process injection"
        tlp         = "TLP:WHITE"
        reference   = "https://attack.mitre.org/techniques/T1055/"
        version     = "2.0"

    strings:
        // Credential theft (strings spécifiques, pas "password" tout seul)
        $cred_1 = "Login Data"                 ascii nocase   // Chrome/Edge credential DB
        $cred_2 = "CryptUnprotectData"         ascii nocase   // Decryption API DPAPI
        $cred_3 = "wallet.dat"                 ascii nocase   // wallets crypto
        $cred_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Credential" ascii nocase
        $cred_5 = "logins.json"                ascii nocase   // Firefox credentials

        // HTTP C2 (form-urlencoded POST = exfiltration classique)
        $http_1 = "Content-Type: application/x-www-form-urlencoded" ascii
        $http_2 = "Content-Type: multipart/form-data"               ascii
        $http_3 = "User-Agent: Mozilla/"                            ascii

        // Obfuscated PowerShell (EncodedCommand = base64)
        $ps_1 = "-EncodedCommand" ascii nocase
        $ps_2 = "-enc "           ascii nocase   // abbreviated form
        $ps_3 = "-nop"            ascii nocase   // -NoProfile
        $ps_4 = "FromBase64String" ascii nocase  // .NET decode

        // Autres TTPs utiles
        $misc_1 = "cmd.exe /c "    ascii nocase
        $misc_2 = "schtasks /create" ascii nocase  // persistence
        $misc_3 = "reg add"          ascii nocase  // persistence via registre

    condition:
        // Structural prerequisites: valid PE, reasonable size, unsigned
        uint16(0) == 0x5A4D                          // MZ header
        and filesize < 5MB
        and pe.number_of_sections > 0                // at least one PE section
        and pe.number_of_sections < 16               // not some weird packed binary

        and ((2 of ($cred_*)) // Branch 1: credential theft, at least 2 indicators

            or

            // Branch 2: HTTP C2 : form-urlencoded header + another signal
            (($http_1 or $http_2) and ($http_3 or 1 of ($cred_*)))

            or

            // Branch 3: Obfuscated PowerShell, at least 2 PS flags
            (2 of ($ps_*))

            or

            // Branch 4: injection, actual imports into the PE table (NOT strings!)
            (
                pe.imports("kernel32.dll", "VirtualAllocEx")
                and pe.imports("kernel32.dll", "WriteProcessMemory")
                and (
                    pe.imports("kernel32.dll", "CreateRemoteThread")
                    or pe.imports("kernel32.dll", "CreateRemoteThreadEx")
                    or pe.imports("ntdll.dll", "NtCreateThreadEx")
                )
            )

            or

            // Branche 5 : persistence (schtasks or reg add + cmd)
            ($misc_2 or $misc_3) and $misc_1
        )
}