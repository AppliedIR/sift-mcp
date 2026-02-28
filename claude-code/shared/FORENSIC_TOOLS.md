# Forensic Tools Reference

Comprehensive reference for forensic analysis tools on the SIFT Workstation.
**Verified:** 2026-02-04 on Ubuntu 24.04.3 LTS (SIFT)

---

## Quick Tool Selection

| Evidence Type | Primary Tool | Alternative |
|---------------|--------------|-------------|
| Windows Event Logs (.evtx) | `EvtxECmd` | `evtxexport` |
| MFT / Filesystem | `MFTECmd` | `fls`, `icat` |
| Registry Hives | `RECmd`, `rip.pl` | `regfexport` |
| Memory Dumps | `vol` (Volatility3) | - |
| Disk Images | `mmls`, `fls` | `ewfinfo` |
| Amcache | `AmcacheParser` | - |
| Jump Lists | `JLECmd` | - |
| LNK Files | `LECmd` | - |
| ShellBags | `SBECmd` | - |
| Browser Artifacts | `SQLECmd` | `sqlite3` |
| Timeline Creation | `log2timeline.py` | `mactime` |
| Malware Detection | `clamscan` | `vol malfind` |
| String Extraction | `bstrings`, `strings` | `bulk_extractor` |
| PST/Email | `pffexport`, `readpst` | - |
| PE Analysis | `readpe`, `pehash` | `r2` |

---

## EZ Tools Linux Limitations

**Windows-only (NOT available on SIFT):**
- **PECmd** (Prefetch parser)
- **SrumECmd** (SRUM parser)

**Workarounds:**
- **Prefetch:** `log2timeline.py --parsers prefetch`
- **SRUM:** Copy `SRUDB.dat` to Windows, or use `esedbexport` + manual parsing

> **Prefetch interpretation caveats:** Prefetch proves execution and execution count, but has no user attribution — corroborate with UserAssist, BAM, or Security logs. Prefetch may be disabled on SSD-only systems or via group policy. The .pf filename hash incorporates the executable path, so the same binary from different paths creates different .pf files. Windows 8+ stores up to 8 last-run timestamps (not just one).

---

## Memory Analysis

### vol (Volatility 3 Framework 2.26.2)
**Path:** `/usr/local/bin/vol`

```bash
# System info
vol -f memory.dmp windows.info

# Process listing
vol -f memory.dmp windows.pslist
vol -f memory.dmp windows.pstree
vol -f memory.dmp windows.psscan        # Find hidden processes

# Process details
vol -f memory.dmp windows.cmdline
vol -f memory.dmp windows.dlllist
vol -f memory.dmp windows.dlllist --pid 1234

# Network
vol -f memory.dmp windows.netstat
vol -f memory.dmp windows.netscan

# Malware detection
vol -f memory.dmp windows.malfind
vol -f memory.dmp windows.hollowprocesses

# Registry
vol -f memory.dmp windows.registry.hivelist
vol -f memory.dmp windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"

# Services
vol -f memory.dmp windows.svcscan

# File extraction
vol -f memory.dmp windows.filescan
vol -f memory.dmp windows.dumpfiles --virtaddr 0xXXXX

# Handles
vol -f memory.dmp windows.handles --pid 1234

# Memory dump
vol -f memory.dmp windows.memmap --pid 1234 --dump

# Environment variables
vol -f memory.dmp windows.envars

# SSDT hooks
vol -f memory.dmp windows.ssdt

# Timeline
vol -f memory.dmp timeliner.Timeliner
```

**Triage workflow:**
```bash
vol -f memory.dmp windows.info > vol_info.txt
vol -f memory.dmp windows.pstree > vol_pstree.txt
vol -f memory.dmp windows.netscan > vol_netscan.txt
vol -f memory.dmp windows.malfind > vol_malfind.txt
vol -f memory.dmp windows.cmdline > vol_cmdline.txt
```

> **Interpretation caveats:** `malfind` flags memory regions with PAGE_EXECUTE_READWRITE — common in packed/injected code but also in JIT compilers, .NET CLR, and games. Not all malfind hits are malicious. Hollow process indicators (unmapped image) require corroboration with process tree, network connections, and parent process. Always check if the flagged region belongs to a known runtime before concluding injection.

---

## Zimmerman Tools

**Location:** `/usr/local/bin/`

All tools output CSV by default with `--csv /output/dir`.

### MFTECmd - Master File Table
```bash
# Parse $MFT
MFTECmd -f '/path/to/$MFT' --csv /output/dir

# Body file for timeline
MFTECmd -f '/path/to/$MFT' --body /output/dir --bodyf mft.body

# Parse $J (UsnJrnl)
MFTECmd -f '/path/to/$J' --csv /output/dir
```

> **Interpretation caveats:** MFT proves file existence, not execution. $STANDARD_INFORMATION timestamps can be trivially modified via SetFileTime API (timestomping). Compare SI timestamps with $FILE_NAME timestamps — FN timestamps cannot be modified by user-mode APIs. SI timestamps earlier than FN timestamps strongly indicate timestomping. Last access time is disabled by default since Vista.

### EvtxECmd - Event Logs
```bash
# Single file
EvtxECmd -f /path/to/Security.evtx --csv /output/dir

# Directory of EVTX
EvtxECmd -d /path/to/evtx_folder --csv /output/dir

# With maps
EvtxECmd -d /path/to/evtx --csv /output/dir --maps /path/to/Maps
```

> **Interpretation caveats:** Event log timestamps can be affected by clock skew and timezone misconfiguration. Cleared logs (Event ID 1102) prove clearing occurred but do not mean no events happened — check other log channels. Security 4624 Logon Type matters: Type 2=interactive, 3=network, 10=RDP. Event 4688 command-line logging must be explicitly enabled via group policy — absence of command lines does not mean absence of execution. System.evtx has a configurable max size (default 20MB) and may only retain days to weeks on active systems.

### RECmd - Registry
```bash
# Parse hive with all plugins
RECmd -f /path/to/NTUSER.DAT --csv /output/dir

# Directory of hives
RECmd -d /path/to/registry_hives --csv /output/dir

# Specific key
RECmd -f /path/to/SOFTWARE --kn "Microsoft\Windows\CurrentVersion\Run" --csv /output/dir

# Batch file
RECmd -f /path/to/SYSTEM --bn /path/to/BatchExamples/Kroll_Batch.reb --csv /output/dir
```

> **Interpretation caveats:** Registry key LastWriteTime applies to the entire key, not individual values. Any modification to any value under a key updates the timestamp — you cannot determine which value changed. Run key entries only execute when the relevant logon/startup event occurs. Check both HKLM and HKCU, plus Wow6432Node equivalents on 64-bit systems.

### AmcacheParser - Execution Evidence
```bash
AmcacheParser -f /path/to/Amcache.hve --csv /output/dir
AmcacheParser -f /path/to/Amcache.hve --csv /output/dir -i    # Include PDB info
```

> **Interpretation caveats:** Amcache proves file presence, not execution. The FileKeyLastWriteTimestamp is often mistaken for execution time. SHA1 hash is recorded at metadata time, not runtime. Corroborate with Prefetch, UserAssist, or BAM for actual execution evidence. Amcache entries persist after uninstall — presence does not prove current installation.

### AppCompatCacheParser - ShimCache
```bash
AppCompatCacheParser -f /path/to/SYSTEM --csv /output/dir
```

> **Interpretation caveats:** ShimCache proves file existence only — on Windows 8+, the execute flag was removed. The timestamp reflects the file's last modification time from $STANDARD_INFORMATION, not when it was cached or executed. ShimCache writes to registry only on clean shutdown; live system cache resides in memory. Limited to ~1024 entries on Win10 — absence proves nothing.

### JLECmd - Jump Lists
```bash
JLECmd -d /path/to/AutomaticDestinations --csv /output/dir
JLECmd -d /path/to/CustomDestinations --csv /output/dir
JLECmd -d /path/to/AutomaticDestinations --csv /output/dir --ld   # With LNK details
```
**Location:** `%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations`

### LECmd - LNK Files
```bash
LECmd -f /path/to/shortcut.lnk --csv /output/dir
LECmd -d /path/to/Recent --csv /output/dir
LECmd -d /path/to/Recent --csv /output/dir --all   # All timestamps
```

### SBECmd - ShellBags
```bash
SBECmd -d /path/to/UsrClass.dat --csv /output/dir
SBECmd -d /path/to/NTUSER.DAT --csv /output/dir
```

### RBCmd - Recycle Bin
```bash
RBCmd -d '/path/to/$Recycle.Bin' --csv /output/dir
RBCmd -f '/path/to/$I*' --csv /output/dir
```

### WxTCmd - Windows Timeline
```bash
WxTCmd -f /path/to/ActivitiesCache.db --csv /output/dir
```
**Location:** `%USERPROFILE%\AppData\Local\ConnectedDevicesPlatform\<folder>\ActivitiesCache.db`

### SQLECmd - SQLite Databases
```bash
SQLECmd -d /path/to/browser_data --csv /output/dir --maps /path/to/Maps
SQLECmd -f /path/to/History --csv /output/dir
```

### bstrings - String Extraction
```bash
bstrings -f /path/to/file -o /output/strings.txt
bstrings -f /path/to/file -o /output/strings.txt -l 8    # Min length 8
bstrings -f /path/to/file -o /output/strings.txt -a      # Unicode + ASCII
```

---

## Timeline Tools

### log2timeline.py / Plaso (20250918)
**Path:** `/usr/bin/log2timeline.py`

```bash
# From disk image
log2timeline.py /output/timeline.plaso /path/to/image.E01

# From directory
log2timeline.py /output/timeline.plaso /path/to/mounted_image/

# Specific parsers
log2timeline.py --parsers 'winevtx,prefetch,mft' /output/timeline.plaso /path/to/evidence

# List parsers
log2timeline.py --parsers list
```

### psort.py - Timeline Processing
**Path:** `/usr/bin/psort.py`

```bash
# Export to CSV
psort.py -o l2tcsv /output/timeline.plaso > timeline.csv

# Filter by date
psort.py -o l2tcsv /output/timeline.plaso "date > '2024-01-01' AND date < '2024-02-01'" > filtered.csv
```

### pinfo.py - Timeline Info
**Path:** `/usr/bin/pinfo.py`

```bash
pinfo.py /path/to/timeline.plaso
```

### mactime - Bodyfile Timeline
**Path:** `/usr/bin/mactime`

```bash
# From bodyfile
mactime -b bodyfile.txt -d > timeline.csv

# Date range
mactime -b bodyfile.txt -d 2024-01-01..2024-02-01 > filtered.csv
```

---

## Sleuth Kit (4.11.1)

**Location:** `/usr/bin/`

### mmls - Partition Layout
```bash
mmls image.dd
mmls image.E01
mmls -a image.dd    # Include unallocated
```

### fls - File Listing
```bash
fls -o 2048 image.dd                    # Root directory
fls -r -o 2048 image.dd                 # Recursive
fls -d -r -o 2048 image.dd              # Deleted only
fls -r -m "/" -o 2048 image.dd > body.txt   # Bodyfile format
```

### icat - Extract by Inode
```bash
icat -o 2048 image.dd 12345 > file
icat -o 2048 image.dd 12345-128-1 > file    # NTFS with stream
```

### fsstat - Filesystem Info
```bash
fsstat -o 2048 image.dd
```

### blkcat - Extract Blocks
```bash
blkcat -o 2048 image.dd 1000 10 > blocks.raw
```

### blkls - List Data Units
```bash
blkls -o 2048 image.dd > unallocated.raw    # Unallocated space
blkls -e -o 2048 image.dd > slack.raw       # Slack space
```

### blkstat - Block Status
```bash
blkstat -o 2048 image.dd 1000
```

### ifind - Find Inode by Name
```bash
ifind -n filename -o 2048 image.dd
```

### ffind - Find Name by Inode
```bash
ffind -o 2048 image.dd 12345
```

### img_stat - Image Info
```bash
img_stat image.dd
img_stat image.E01
```

### img_cat - Output Image Contents
```bash
img_cat image.E01 > image.raw
```

### istat - Inode Details
```bash
istat -o 2048 image.dd 12345
```

### jcat - Journal Entry
```bash
jcat -o 2048 image.dd 1234
```

### jls - Journal List
```bash
jls -o 2048 image.dd
```

### hfind - Hash Lookup
```bash
hfind /path/to/hashdb hashvalue
```

### tsk_recover - File Recovery
```bash
tsk_recover -o 2048 -e image.dd /output/dir
```

### tsk_gettimes - Get Timestamps
```bash
tsk_gettimes -o 2048 image.dd
```

### tsk_loaddb - Load to SQLite
```bash
tsk_loaddb -o 2048 image.dd /output/case.db
```

### sorter - Categorize Files
```bash
sorter -o 2048 -d /output/dir image.dd
```

### sigfind - Signature Search
```bash
sigfind -o 2048 0x504B0304 image.dd    # ZIP signature
```

### fiwalk - XML Output
```bash
fiwalk -X image.dd > fiwalk.xml
```

---

## Disk Image Tools

### EWF Tools (E01 Format)
**Location:** `/usr/bin/`

```bash
# Info
ewfinfo image.E01

# Verify integrity
ewfverify image.E01

# Mount as raw
ewfmount image.E01 /mnt/ewf

# Acquire image
ewfacquire /dev/sda
ewfacquire -t evidence -c best -S 2G /dev/sda
```

### AFF Tools
**Location:** `/usr/bin/`

```bash
affinfo image.aff
affcat image.aff > image.raw
affconvert -o image.aff image.raw
affcompare image1.aff image2.aff
```

### QEMU Image Tools
**Location:** `/usr/bin/`

```bash
qemu-img info image.vmdk
qemu-img convert -O raw image.vmdk image.raw
qemu-nbd -c /dev/nbd0 image.qcow2
```

### xmount - Virtual Mounting
**Path:** `/usr/bin/xmount`

```bash
xmount --in ewf image.E01 --out raw /mnt/point
xmount --in raw image.dd --out vdi /mnt/point
```

---

## Forensic Imaging

### dc3dd
**Path:** `/usr/bin/dc3dd`

```bash
dc3dd if=/dev/sda of=image.dd hash=sha256 log=image.log
dc3dd if=/dev/sda of=image.dd.000 ofsz=2G hash=sha256   # Split
```

### dcfldd
**Path:** `/usr/bin/dcfldd`

```bash
dcfldd if=/dev/sda of=image.dd hash=sha256 hashlog=hashes.txt
```

### ddrescue
**Path:** `/usr/bin/ddrescue`

```bash
ddrescue -d /dev/sda image.dd logfile.log
ddrescue -d -r3 /dev/sda image.dd logfile.log   # Retry 3 times
```

---

## Registry Tools

### rip.pl (RegRipper)
**Path:** `/usr/local/bin/rip.pl`

```bash
# All plugins
rip.pl -r /path/to/NTUSER.DAT -a > output.txt

# Specific plugin
rip.pl -r /path/to/SYSTEM -p services

# List plugins
rip.pl -l
```

**Common plugins:**
- NTUSER.DAT: `userassist`, `recentdocs`, `typedurls`, `runmru`
- SYSTEM: `services`, `shimcache`, `bam`
- SOFTWARE: `run`, `profilelist`, `uninstall`
- SAM: `samparse`

### regfinfo / regfexport (libregf)
**Location:** `/usr/bin/`

```bash
regfinfo /path/to/NTUSER.DAT
regfexport /path/to/NTUSER.DAT
```

---

## Windows Artifact Libraries

### libesedb (ESE Databases)
**Location:** `/usr/bin/`

```bash
esedbinfo /path/to/database.edb
esedbexport /path/to/database.edb
```
Use for: SRUM, Exchange, Windows Search

### libevt / libevtx (Event Logs)
**Location:** `/usr/bin/`

```bash
# Legacy EVT
evtinfo /path/to/file.evt
evtexport /path/to/file.evt

# EVTX
evtxinfo /path/to/file.evtx
evtxexport /path/to/file.evtx > events.xml
```

### libfvde (FileVault)
**Location:** `/usr/bin/`

```bash
fvdeinfo /path/to/EncryptedRoot.plist.wipekey
fvdemount /path/to/device /mnt/point
```

### libpff (PST/OST Files)
**Location:** `/usr/bin/`

```bash
pffinfo /path/to/file.pst
pffexport /path/to/file.pst
```

### libvshadow (Volume Shadow Copies)
**Location:** `/usr/bin/`

```bash
vshadowinfo /path/to/image
vshadowmount /path/to/image /mnt/vss
```

### readpst (PST to mbox)
**Path:** `/usr/bin/readpst`

```bash
readpst -o /output/dir /path/to/file.pst
readpst -r -o /output/dir /path/to/file.pst   # Recursive
```

---

## Malware Analysis

### ClamAV
**Location:** `/usr/bin/`

```bash
sudo freshclam                    # Update signatures

clamscan /path/to/file
clamscan -r /path/to/directory    # Recursive
clamscan -r -i /path/to/directory # Infected only
clamscan -r --detect-pua --detect-structured /path/to/directory
```

### pev (PE Analysis)
**Location:** `/usr/bin/`

```bash
readpe /path/to/file.exe          # PE info
readpe -S /path/to/file.exe       # Sections
pehash /path/to/file.exe          # Hashes
pescan /path/to/file.exe          # Anomaly detection
pestr /path/to/file.exe           # Strings
```

### radare2
**Path:** `/usr/bin/radare2`, `/usr/bin/r2`

```bash
r2 -A /path/to/binary

# Commands inside r2:
# aaa    - analyze all
# afl    - list functions
# pdf    - disassemble function
# iz     - strings
# iI     - binary info
# ii     - imports
# ie     - exports
# V      - visual mode
```

### upx (Unpacker)
**Path:** `/usr/bin/upx`

```bash
upx -t /path/to/file.exe              # Test if packed
upx -d /path/to/file.exe -o unpacked.exe   # Unpack
```

### ssdeep (Fuzzy Hashing)
**Path:** `/usr/bin/ssdeep`

```bash
ssdeep /path/to/file                  # Generate hash
ssdeep -d file1 file2                 # Compare
ssdeep -m known.txt suspect           # Match against DB
ssdeep -r -d /path/to/samples         # Recursive compare
```

---

## Hash Tools

### hashdeep / md5deep / sha256deep
**Path:** `/usr/bin/hashdeep`

```bash
md5deep -r /path/to/directory > hashes.txt
sha256deep -r /path/to/directory > hashes.txt
hashdeep -r -m known.txt /path/to/directory     # Compare
hashdeep -r -a -k known.txt /path/to/directory  # Audit mode
```

---

## Crypto Tools

### aeskeyfind / rsakeyfind
**Location:** `/usr/bin/`

```bash
aeskeyfind memory.dmp
rsakeyfind memory.dmp
```

### cryptsetup (LUKS)
**Path:** `/usr/sbin/cryptsetup`

```bash
cryptsetup luksDump /dev/sda1
cryptsetup luksOpen /dev/sda1 decrypted
```

### dislocker (BitLocker)
**Path:** `/usr/bin/dislocker`

```bash
dislocker -V /dev/sda1 -u -- /mnt/bitlocker
mount -o loop /mnt/bitlocker/dislocker-file /mnt/windows
```

### ccrypt
**Path:** `/usr/bin/ccrypt`

```bash
ccrypt -e file.txt    # Encrypt
ccrypt -d file.txt.cpt   # Decrypt
```

---

## Recovery Tools

### photorec
**Path:** `/usr/bin/photorec`

```bash
photorec image.dd
```
Interactive tool for file carving.

### testdisk
**Path:** `/usr/bin/testdisk`

```bash
testdisk image.dd
```
Interactive partition recovery.

### extundelete
**Path:** `/usr/bin/extundelete`

```bash
extundelete --restore-all /dev/sda1
extundelete --restore-file path/to/file /dev/sda1
```

---

## Carving Tools

### foremost
**Path:** `/usr/bin/foremost`

```bash
foremost -i image.dd -o /output/dir
foremost -t jpg,pdf,doc -i image.dd -o /output/dir   # Specific types
```

### scalpel
**Path:** `/usr/bin/scalpel`

```bash
scalpel -c /etc/scalpel/scalpel.conf -o /output/dir image.dd
```

### bulk_extractor
**Path:** `/usr/bin/bulk_extractor`

```bash
bulk_extractor -o /output/dir image.dd
bulk_extractor -o /output/dir capture.pcap
bulk_extractor -o /output/dir -x all -e email -e url image.dd   # Specific
```
**Output:** emails, URLs, credit cards, domains, etc.

---

## Network Forensics

### tcpdump
**Path:** `/usr/bin/tcpdump`

```bash
tcpdump -r capture.pcap
tcpdump -r capture.pcap -w filtered.pcap 'host 192.168.1.1'
tcpdump -r capture.pcap -X   # Hex + ASCII
```

### tcpflow
**Path:** `/usr/bin/tcpflow`

```bash
tcpflow -r capture.pcap -o /output/dir
tcpflow -r capture.pcap -o /output/dir -T %T_%A-%B.flow
```

### wireshark
**Path:** `/usr/bin/wireshark`

```bash
wireshark capture.pcap
```

### ngrep
**Path:** `/usr/bin/ngrep`

```bash
ngrep -I capture.pcap 'password'
ngrep -I capture.pcap -W byline 'HTTP'
```

### tcpreplay
**Path:** `/usr/bin/tcpreplay`

```bash
tcpreplay -i eth0 capture.pcap
```

### tcpstat
**Path:** `/usr/bin/tcpstat`

```bash
tcpstat -r capture.pcap
```

### tcptrace
**Path:** `/usr/bin/tcptrace`

```bash
tcptrace capture.pcap
tcptrace -l capture.pcap   # Long output
```

### tcptrack
**Path:** `/usr/bin/tcptrack`

```bash
tcptrack -i eth0
tcptrack -r capture.pcap
```

### tcpxtract
**Path:** `/usr/bin/tcpxtract`

```bash
tcpxtract -f capture.pcap -o /output/dir
```

### tcpick
**Path:** `/usr/sbin/tcpick`

```bash
tcpick -r capture.pcap -yP   # Payload
```

### netcat
**Path:** `/usr/bin/netcat` (also `nc`)

```bash
nc -l -p 4444                # Listen
nc host 4444 < file          # Send file
```

### dsniff
**Path:** `/usr/sbin/dsniff`

```bash
dsniff -p capture.pcap
```

### ettercap
**Path:** `/usr/bin/ettercap`

```bash
ettercap -T -r capture.pcap
```

### arp-scan
**Path:** `/usr/sbin/arp-scan`

```bash
arp-scan --localnet
arp-scan -I eth0 192.168.1.0/24
```

### nbtscan
**Path:** `/usr/bin/nbtscan`

```bash
nbtscan 192.168.1.0/24
```

### nfdump
**Path:** `/usr/bin/nfdump`

```bash
nfdump -r nfcapd.file
nfdump -r nfcapd.file 'src ip 192.168.1.1'
```

---

## File Analysis

### exiftool
**Path:** `/usr/local/bin/exiftool`

```bash
exiftool /path/to/file
exiftool -r /path/to/directory
exiftool -CreateDate -GPSLatitude -GPSLongitude /path/to/image.jpg
```

### exif
**Path:** `/usr/bin/exif`

```bash
exif /path/to/image.jpg
```

### file
**Path:** `/usr/bin/file`

```bash
file /path/to/file
file -i /path/to/file   # MIME type
```

### strings
**Path:** `/usr/bin/strings`

```bash
strings /path/to/file
strings -a /path/to/file     # All sections
strings -e l /path/to/file   # Little-endian UTF-16
```

### xxd
**Path:** `/usr/bin/xxd`

```bash
xxd /path/to/file | head
xxd -s 0x100 -l 256 /path/to/file   # Offset + length
```

### hexdump
**Path:** `/usr/bin/hexdump`

```bash
hexdump -C /path/to/file | head
```

### hexedit
**Path:** `/usr/bin/hexedit`

```bash
hexedit /path/to/file
```

### ghex
**Path:** `/usr/bin/ghex`

GUI hex editor.

---

## Utilities

### sqlite3
**Path:** `/usr/bin/sqlite3`

```bash
sqlite3 database.db ".tables"
sqlite3 database.db "SELECT * FROM table_name;"
sqlite3 -header -csv database.db "SELECT * FROM table;" > output.csv
```

### jq
**Path:** `/usr/bin/jq`

```bash
cat file.json | jq '.'
cat file.json | jq '.key'
cat file.json | jq '.[] | select(.field == "value")'
```

### 7z / p7zip
**Path:** `/usr/bin/7z`, `/usr/bin/p7zip`

```bash
7z x archive.7z
7z l archive.7z    # List
7z e archive.7z -o/output/dir
```

### unrar
**Path:** `/usr/bin/unrar`

```bash
unrar x archive.rar
unrar l archive.rar
```

### cabextract
**Path:** `/usr/bin/cabextract`

```bash
cabextract file.cab
cabextract -d /output/dir file.cab
```

---

## Autopsy
**Path:** `/usr/bin/autopsy`

```bash
autopsy
```
Web-based GUI at http://localhost:9999/autopsy

---

## Optional Tools (Not Pre-installed)

These tools enhance SIFT but require separate installation:

| Tool | Purpose | Installation |
|------|---------|--------------|
| **Hayabusa** | Fast EVTX timeline/detection | [GitHub Releases](https://github.com/Yamato-Security/hayabusa/releases) |
| **Chainsaw** | Sigma-based EVTX hunting | [GitHub Releases](https://github.com/WithSecureLabs/chainsaw/releases) |
| **YARA** | Pattern matching rules | `sudo apt install yara` |
| **tshark** | CLI Wireshark | `sudo apt install tshark` |
| **binwalk** | Firmware analysis | `sudo apt install binwalk` |
| **hashcat** | Password cracking | `sudo apt install hashcat` |
| **john** | Password cracking | `sudo apt install john` |

**Recommendations:**
- **Hayabusa** - Highly recommended for EVTX triage with Sigma rules
- **YARA** - Essential for custom malware hunting rules
- **tshark** - CLI pcap analysis

---

## Tool Locations Summary

| Category | Location |
|----------|----------|
| Zimmerman Tools | `/usr/local/bin/` |
| Volatility3 | `/usr/local/bin/vol` |
| RegRipper | `/usr/local/bin/rip.pl` |
| exiftool | `/usr/local/bin/exiftool` |
| Sleuth Kit | `/usr/bin/` |
| Plaso | `/usr/bin/` |
| EWF/AFF Tools | `/usr/bin/` |
| Network Tools | `/usr/bin/`, `/usr/sbin/` |
| libevtx/libregf | `/usr/bin/` |

---

## Common Workflows

### Windows Triage
```bash
# 1. Registry
RECmd -f NTUSER.DAT --csv /output
RECmd -f SYSTEM --csv /output
AmcacheParser -f Amcache.hve --csv /output
AppCompatCacheParser -f SYSTEM --csv /output

# 2. Event Logs
EvtxECmd -d /evtx --csv /output

# 3. Filesystem
MFTECmd -f '$MFT' --csv /output
JLECmd -d AutomaticDestinations --csv /output
LECmd -d Recent --csv /output

# 4. User Activity
SBECmd -f UsrClass.dat --csv /output
WxTCmd -f ActivitiesCache.db --csv /output
```

### Memory Triage
```bash
vol -f memory.dmp windows.info > info.txt
vol -f memory.dmp windows.pstree > pstree.txt
vol -f memory.dmp windows.cmdline > cmdline.txt
vol -f memory.dmp windows.netscan > netscan.txt
vol -f memory.dmp windows.malfind > malfind.txt
vol -f memory.dmp windows.svcscan > svcscan.txt
```

### Malware Triage
```bash
file suspect.exe
sha256sum suspect.exe
strings suspect.exe | head -100
clamscan suspect.exe
readpe suspect.exe
pehash suspect.exe
ssdeep suspect.exe
r2 -A suspect.exe
```

---

## Notes

1. **Always specify output directory** for tools that write multiple files
2. **Path handling** - Windows artifacts have special characters (`$MFT`, `$J`)
3. **Timestamps** - Most tools use UTC; clarify timezone in reports
4. **Large files** - Consider filtering for MFT, large EVTX collections
5. **Chaining** - Zimmerman CSV works well with grep/awk
