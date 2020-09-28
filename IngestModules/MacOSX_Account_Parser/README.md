- __Description:__ Parse OSX 10.8+ account .plist files and extract any available attributes. If a hashed password is available, 
extract it and present it in a format that can be used with [Hashcat](https://hashcat.net/).
- __Author:__ Luke Gaddie
- __Minimum Autopsy version:__ 4.0.0
- __License:__ [MIT](https://opensource.org/licenses/MIT), with the exception of dependencies: 
    - [biplist](https://pypi.org/project/biplist/) - BSD License (BSD)

## Installation & Usage
Copy MacOSX_Account_Parser into your Autopsy Python Plugins Folder.

Run Ingest modules against your data source, making sure to enable to "MacOSX Account Parser" module.

Any extracted account information will be placed in one of two spots: 

- Extracted Content
    - Operating System User Account
    - Hashed Credentials

## Hashcat Usage

In the event that hashed credentials can be extracted from the user account, they'll be placed in "Extracted Content" ->
"Hashed Credentials".

Assuming that you place the "Hashcat Entry" value found in an artifact in hashes.txt, a sample hashcat session might look like: 

```
C:\hashcat> hashcat64.exe -m 7100 ./hashes.txt ./dictionary.txt
hashcat (v5.1.0) starting...

[...]

Approaching final keyspace - workload adjusted.

$ml$68027$fccff02010450ae731c883d638b2a3028bf6504937bab584c283a3a44e8f7ad8$e945d8df4ca67261ff45b07a71e5d695816c53532b42988ae1e91268e869c877ef0186a4b2bdaa75d4b316d03274f5b453ee1c5fef067638041fc696fd091400:TestPassword

Session..........: hashcat
Status...........: Cracked
Hash.Type........: macOS v10.8+ (PBKDF2-SHA512)
Hash.Target......: $ml$68027$fccff02010450ae731c883d638b2a3028bf650493...091400
Time.Started.....: Mon Sep 28 18:01:20 2020 (1 sec)
Time.Estimated...: Mon Sep 28 18:01:21 2020 (0 secs)
Guess.Base.......: File (dictionary.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#2.........:        2 H/s (0.45ms) @ Accel:64 Loops:32 Thr:64 Vec:1
Speed.#3.........:        0 H/s (0.00ms) @ Accel:64 Loops:32 Thr:64 Vec:1
Speed.#*.........:        2 H/s
Recovered........: 1/1 (100.00%) Digests, 1/1 (100.00%) Salts
Progress.........: 2/2 (100.00%)
Rejected.........: 0/2 (0.00%)
Restore.Point....: 0/2 (0.00%)
Restore.Sub.#2...: Salt:0 Amplifier:0-1 Iteration:68000-68026
Restore.Sub.#3...: Salt:0 Amplifier:0-0 Iteration:0-32
Candidates.#2....: TestPassword -> hashcat
Candidates.#3....: [Copying]
Hardware.Mon.#2..: Temp: 58c Fan: 41% Util: 87% Core:1936MHz Mem:4513MHz Bus:8
Hardware.Mon.#3..: Temp: 53c Fan: 36% Util:  0% Core:1695MHz Mem:4513MHz Bus:8

``` 

## Misc. Information

* Accounts are stored in /private/var/db/dslocal/nodes/Default/*.plist
* Credentials are hashed as SALTED-SHA512-PBKDF2 (Hashcat -m 7100)
* Hashes are formatted as $ml$[iterations]$[salt]$[first 128 bits of entropy]