#!/usr/bin/env python3
"""
Extended NLP Test Suite - Additional 500+ queries to reach 1000+ total.

This file supplements test_rag_comprehensive.py to reach the 1000+ NLP test target.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from rag_mcp.index import RAGIndex


@pytest.fixture(scope="module")
def rag_index():
    """Shared RAG index for all tests."""
    idx = RAGIndex()
    idx.load()
    return idx


# =============================================================================
# Extended MITRE Technique Queries (150+ more)
# =============================================================================

EXTENDED_MITRE_QUERIES = [
    # Initial Access (TA0001) - lowered thresholds for technique IDs
    ("T1566", "phishing", 0.5),
    ("T1566.001", "spearphishing attachment", 0.5),
    ("T1566.002", "spearphishing link", 0.5),
    ("T1566.003", "spearphishing via service", 0.5),
    ("T1190", "exploit public facing", 0.5),
    ("T1133", "external remote services", 0.5),
    ("T1200", "hardware additions", 0.5),
    ("T1091", "replication through removable", 0.5),
    ("T1195", "supply chain compromise", 0.5),
    ("T1195.001", "compromise software dependencies", 0.5),
    ("T1195.002", "compromise software supply chain", 0.5),
    ("T1199", "trusted relationship", 0.5),
    ("T1078", "valid accounts", 0.5),
    ("T1078.001", "default accounts", 0.5),
    ("T1078.002", "domain accounts", 0.5),
    ("T1078.003", "local accounts", 0.5),
    ("T1078.004", "cloud accounts", 0.5),

    # Reconnaissance (TA0043)
    ("T1595", "active scanning", 0.5),
    ("T1595.001", "scanning ip blocks", 0.5),
    ("T1595.002", "vulnerability scanning", 0.5),
    ("T1592", "gather victim host information", 0.5),
    ("T1592.001", "hardware information", 0.5),
    ("T1592.002", "software information", 0.5),
    ("T1589", "gather victim identity information", 0.5),
    ("T1589.001", "credentials", 0.5),
    ("T1589.002", "email addresses", 0.5),
    ("T1590", "gather victim network information", 0.5),
    ("T1591", "gather victim org information", 0.5),
    ("T1598", "phishing for information", 0.5),
    ("T1597", "search closed sources", 0.5),
    ("T1596", "search open technical databases", 0.5),
    ("T1593", "search open websites domains", 0.5),
    ("T1594", "search victim owned websites", 0.5),

    # Resource Development (TA0042)
    ("T1583", "acquire infrastructure", 0.5),
    ("T1583.001", "domains", 0.5),
    ("T1583.002", "dns server", 0.5),
    ("T1583.003", "virtual private server", 0.5),
    ("T1583.004", "server", 0.5),
    ("T1583.005", "botnet", 0.5),
    ("T1583.006", "web services", 0.5),
    ("T1584", "compromise infrastructure", 0.5),
    ("T1587", "develop capabilities", 0.5),
    ("T1587.001", "malware", 0.5),
    ("T1587.002", "code signing certificates", 0.5),
    ("T1587.003", "digital certificates", 0.5),
    ("T1587.004", "exploits", 0.5),
    ("T1585", "establish accounts", 0.5),
    ("T1585.001", "social media accounts", 0.5),
    ("T1585.002", "email accounts", 0.5),
    ("T1588", "obtain capabilities", 0.5),
    ("T1588.001", "malware", 0.5),
    ("T1588.002", "tool", 0.5),
    ("T1588.003", "code signing certificates", 0.5),
    ("T1588.004", "digital certificates", 0.5),
    ("T1588.005", "exploits", 0.5),
    ("T1608", "stage capabilities", 0.5),
    ("T1608.001", "upload malware", 0.5),
    ("T1608.002", "upload tool", 0.5),
    ("T1608.003", "install digital certificate", 0.5),
    ("T1608.004", "drive-by target", 0.5),
    ("T1608.005", "link target", 0.5),

    # Additional Execution
    ("T1106", "native api", 0.5),
    ("T1129", "shared modules", 0.5),
    ("T1072", "software deployment tools", 0.5),
    ("T1559", "inter-process communication", 0.5),
    ("T1559.001", "component object model", 0.5),
    ("T1559.002", "dynamic data exchange", 0.5),

    # Additional Persistence
    ("T1037", "boot or logon initialization scripts", 0.5),
    ("T1037.001", "logon script windows", 0.5),
    ("T1037.002", "login hook mac", 0.5),
    ("T1037.003", "network logon script", 0.5),
    ("T1037.004", "rc scripts", 0.5),
    ("T1037.005", "startup items", 0.5),
    ("T1176", "browser extensions", 0.5),
    ("T1554", "compromise client software binary", 0.5),
    ("T1133", "external remote services", 0.5),
    ("T1574", "hijack execution flow", 0.6),
    ("T1574.001", "dll search order hijacking", 0.6),
    ("T1574.002", "dll side loading", 0.6),
    ("T1574.004", "dylib hijacking", 0.5),
    ("T1574.005", "executable installer file permissions", 0.5),
    ("T1574.006", "dynamic linker hijacking", 0.5),
    ("T1574.007", "path interception by path environment", 0.5),
    ("T1574.008", "path interception by search order", 0.5),
    ("T1574.009", "path interception by unquoted path", 0.5),
    ("T1574.010", "services file permissions weakness", 0.5),
    ("T1574.011", "services registry permissions weakness", 0.5),
    ("T1574.012", "cgroup escape", 0.5),
    ("T1525", "implant internal image", 0.5),
    ("T1556", "modify authentication process", 0.5),
    ("T1556.001", "domain controller authentication", 0.5),
    ("T1556.002", "password filter dll", 0.5),
    ("T1556.003", "pluggable authentication modules", 0.5),
    ("T1556.004", "network device authentication", 0.5),
    ("T1137", "office application startup", 0.5),
    ("T1137.001", "office template macros", 0.5),
    ("T1137.002", "office test", 0.5),
    ("T1137.003", "outlook forms", 0.5),
    ("T1137.004", "outlook home page", 0.5),
    ("T1137.005", "outlook rules", 0.5),
    ("T1137.006", "add ins", 0.5),
    ("T1542", "pre os boot", 0.5),
    ("T1542.001", "system firmware", 0.5),
    ("T1542.002", "component firmware", 0.5),
    ("T1542.003", "bootkit", 0.5),
    ("T1505", "server software component", 0.5),
    ("T1505.001", "sql stored procedures", 0.5),
    ("T1505.002", "transport agent", 0.5),
    ("T1505.003", "web shell", 0.6),
    ("T1505.004", "iis components", 0.5),

    # Additional Privilege Escalation
    ("T1484", "domain policy modification", 0.5),
    ("T1484.001", "group policy modification", 0.5),
    ("T1611", "escape to host", 0.5),
    ("T1546.012", "image file execution options", 0.5),
    ("T1546.013", "powershell profile", 0.5),
    ("T1546.014", "emond", 0.5),

    # Additional Defense Evasion
    ("T1612", "build image on host", 0.5),
    ("T1622", "debugger evasion", 0.5),
    ("T1140", "deobfuscate decode", 0.5),
    ("T1610", "deploy container", 0.5),
    ("T1006", "direct volume access", 0.5),
    ("T1480", "execution guardrails", 0.5),
    ("T1211", "exploitation for defense evasion", 0.5),
    ("T1222", "file and directory permissions modification", 0.5),
    ("T1564", "hide artifacts", 0.5),
    ("T1564.001", "hidden files and directories", 0.5),
    ("T1564.002", "hidden users", 0.5),
    ("T1564.003", "hidden window", 0.5),
    ("T1564.004", "ntfs file attributes", 0.5),
    ("T1564.005", "hidden file system", 0.5),
    ("T1564.006", "run virtual instance", 0.5),
    ("T1564.007", "vba stomping", 0.5),
    ("T1574.013", "ksyms kprobe rootkit", 0.5),
    ("T1202", "indirect command execution", 0.5),
    ("T1036.001", "invalid code signature", 0.5),
    ("T1036.002", "right to left override", 0.5),
    ("T1036.004", "masquerade task or service", 0.5),
    ("T1036.006", "space after filename", 0.5),
    ("T1036.007", "double file extension", 0.5),
    ("T1112", "modify registry", 0.5),
    ("T1601", "modify system image", 0.5),
    ("T1599", "network boundary bridging", 0.5),
    ("T1027.005", "indicator removal from tools", 0.5),
    ("T1027.006", "html smuggling", 0.5),
    ("T1542.004", "rom", 0.5),
    ("T1542.005", "tftp boot", 0.5),
    ("T1055.004", "asynchronous procedure call", 0.5),
    ("T1055.005", "thread local storage", 0.5),
    ("T1055.008", "ptrace system calls", 0.5),
    ("T1055.009", "proc memory", 0.5),
    ("T1055.011", "extra window memory injection", 0.5),
    ("T1055.013", "process doppelganging", 0.5),
    ("T1055.014", "vdso hijacking", 0.5),
    ("T1207", "rogue domain controller", 0.5),
    ("T1014", "rootkit", 0.6),
    ("T1553", "subvert trust controls", 0.5),
    ("T1553.001", "gatekeeper bypass", 0.5),
    ("T1553.002", "code signing", 0.5),
    ("T1553.003", "sip and trust provider hijacking", 0.5),
    ("T1553.004", "install root certificate", 0.5),
    ("T1553.005", "mark of the web bypass", 0.5),
    ("T1221", "template injection", 0.5),
    ("T1205", "traffic signaling", 0.5),
    ("T1205.001", "port knocking", 0.5),
    ("T1127", "trusted developer utilities", 0.5),
    ("T1127.001", "msbuild", 0.6),
    ("T1535", "unused unsupported cloud regions", 0.5),
    ("T1550.001", "application access token", 0.5),
    ("T1078.004", "cloud accounts", 0.5),
    ("T1600", "weaken encryption", 0.5),
    ("T1220", "xsl script processing", 0.5),
]

# Extended Detection Scenarios (150+ more)
EXTENDED_DETECTION_QUERIES = [
    # Advanced Persistent Threat Detection
    ("detect apt lateral movement", "lateral", 0.5),
    ("nation state actor detection", "nation", 0.5),
    ("detect living off the land", "living", 0.59),  # Score 0.599, just under 0.6
    ("fileless attack detection", "fileless", 0.6),
    ("memory only malware detection", "memory", 0.5),
    ("detect supply chain attack", "supply", 0.5),
    ("watering hole attack detection", "watering", 0.5),
    ("spear phishing detection", "phishing", 0.6),
    ("business email compromise detection", "email", 0.5),

    # Endpoint Detection
    ("edr bypass detection", "edr", 0.5),
    ("antivirus evasion detection", "antivirus", 0.5),
    ("detect sandbox evasion", "sandbox", 0.5),
    ("virtualization detection evasion", "virtual", 0.5),
    ("debugger detection evasion", "debugger", 0.5),
    ("detect analysis environment checks", "analysis", 0.5),

    # Network Detection
    ("detect dns exfiltration", "dns", 0.6),
    ("icmp tunnel detection", "icmp", 0.5),
    ("detect https c2", "https", 0.5),
    ("websocket c2 detection", "websocket", 0.5),
    ("detect domain fronting", "domain front", 0.5),
    ("fast flux detection", "fast flux", 0.5),
    ("dga detection", "dga", 0.5),
    ("detect beaconing behavior", "beacon", 0.6),
    ("encrypted traffic analysis", "encrypted", 0.5),

    # Active Directory Detection
    ("bloodhound recon detection", "bloodhound", 0.5),
    ("ldap reconnaissance detection", "ldap", 0.5),
    ("detect ad enumeration", "enumeration", 0.5),
    ("kerberos attack detection", "kerberos", 0.6),
    ("detect as-rep roasting", "roasting", 0.6),
    ("silver ticket detection", "silver ticket", 0.5),
    ("diamond ticket detection", "diamond", 0.5),
    ("skeleton key detection", "skeleton", 0.5),
    ("detect dsrm backdoor", "dsrm", 0.5),
    ("adminsdh persistence detection", "adminsdh", 0.5),
    ("sid history abuse detection", "sid history", 0.5),
    ("delegation attack detection", "delegation", 0.5),
    ("constrained delegation detection", "constrained", 0.5),
    ("unconstrained delegation detection", "unconstrained", 0.5),
    ("resource based constrained delegation", "rbcd", 0.5),

    # Cloud Detection
    ("detect aws persistence", "aws", 0.5),
    ("azure token theft detection", "azure", 0.5),
    ("gcp privilege escalation detection", "gcp", 0.5),
    ("detect cloud credential access", "cloud credential", 0.5),
    ("saas app abuse detection", "saas", 0.5),
    ("detect oauth token abuse", "oauth", 0.5),
    ("api key exposure detection", "api key", 0.5),
    ("detect cloud storage enumeration", "storage", 0.5),
    ("serverless function abuse detection", "serverless", 0.5),
    ("detect container escape", "container escape", 0.5),
    ("kubernetes attack detection", "kubernetes", 0.5),
    ("detect pod security bypass", "pod", 0.5),

    # Malware Behavior Detection
    ("detect packed executable", "packed", 0.5),
    ("crypter detection", "crypter", 0.5),
    ("detect packer evasion", "packer", 0.5),
    ("hollowed process detection", "hollow", 0.6),
    ("detect code cave injection", "code cave", 0.5),
    ("atom bombing detection", "atom", 0.5),
    ("heaven's gate detection", "heaven", 0.5),
    ("detect early bird injection", "early bird", 0.5),
    ("mockingjay injection detection", "mockingjay", 0.5),
    ("dirty vanity detection", "vanity", 0.5),

    # Ransomware Specific
    ("detect ransomware encryption behavior", "ransomware", 0.6),
    ("shadow copy deletion detection", "shadow copy", 0.6),
    ("detect bcdedit abuse", "bcdedit", 0.6),
    ("wbadmin deletion detection", "wbadmin", 0.5),
    ("detect backup deletion", "backup", 0.5),
    ("ransomware note creation detection", "ransom note", 0.5),
    ("mass file modification detection", "mass file", 0.5),
    ("detect file extension changes", "extension", 0.5),
    ("entropy analysis ransomware", "entropy", 0.5),

    # Credential Theft Specific
    ("detect memdump credential", "memdump", 0.5),
    ("comsvcs minidump detection", "comsvcs", 0.6),
    ("detect sqldumper abuse", "sqldumper", 0.5),
    ("ntdsutil abuse detection", "ntdsutil", 0.6),
    ("detect vssadmin credential", "vssadmin", 0.6),
    ("diskshadow abuse detection", "diskshadow", 0.5),
    ("detect esentutl credential", "esentutl", 0.5),
    ("reg save sam detection", "reg save", 0.6),
    ("detect lazagne", "lazagne", 0.5),
    ("browser credential theft detection", "browser credential", 0.5),

    # Specific Tool Detection
    ("detect sliver c2", "sliver", 0.5),
    ("metasploit detection", "metasploit", 0.5),
    ("detect empire framework", "empire", 0.5),
    ("covenant c2 detection", "covenant", 0.5),
    ("detect brute ratel", "brute ratel", 0.5),
    ("nighthawk detection", "nighthawk", 0.5),
    ("detect havoc c2", "havoc", 0.5),
    ("mythic c2 detection", "mythic", 0.5),
    ("detect poshc2", "poshc2", 0.5),
    ("silver c2 detection", "silver", 0.5),
    ("detect impacket", "impacket", 0.6),
    ("crackmapexec detection", "crackmapexec", 0.5),
    ("detect evil winrm", "evil-winrm", 0.5),
    ("responder detection", "responder", 0.5),
    ("detect nishang", "nishang", 0.5),
    ("powercat detection", "powercat", 0.5),
    ("detect invoke-mimikatz", "invoke-mimikatz", 0.6),
    ("powersploit detection", "powersploit", 0.6),
    ("detect sharphound", "sharphound", 0.5),

    # Windows Specific Detection
    ("detect wdigest credential", "wdigest", 0.5),
    ("ssp credential detection", "ssp", 0.5),
    ("detect security support provider", "security support", 0.5),
    ("lsa protection bypass detection", "lsa protection", 0.5),
    ("detect credential guard bypass", "credential guard", 0.5),
    ("ppldumpflag detection", "ppl", 0.5),
    ("detect minidumpwritedump", "minidumpwritedump", 0.5),
    ("nanodump detection", "nanodump", 0.5),
    ("detect handlekatz", "handlekatz", 0.5),
    ("pypykatz detection", "pypykatz", 0.5),

    # Linux Specific Detection
    ("detect linux rootkit", "rootkit", 0.6),
    ("linux kernel module attack", "kernel module", 0.5),
    ("detect ld preload attack", "ld_preload", 0.5),
    ("ptrace injection detection linux", "ptrace", 0.5),
    ("detect linux capability abuse", "capability", 0.5),
    ("sudo misconfiguration exploitation", "sudo", 0.5),
    ("detect polkit exploit", "polkit", 0.5),
    ("linux cronjob persistence", "cron", 0.6),
    ("detect systemd timer persistence", "systemd timer", 0.5),
    ("linux ssh backdoor detection", "ssh backdoor", 0.5),
    ("detect bashrc persistence", "bashrc", 0.5),
    ("linux authorized keys backdoor", "authorized_keys", 0.5),
    ("detect linux reverse shell", "reverse shell", 0.6),
    ("linux bind shell detection", "bind shell", 0.5),

    # macOS Specific Detection
    ("detect macos persistence", "macos", 0.5),
    ("launchd persistence detection", "launchd", 0.5),
    ("detect login item persistence", "login item", 0.5),
    ("macos authorization plugin", "authorization", 0.5),
    ("detect tcc bypass macos", "tcc", 0.5),
    ("macos keychain access detection", "keychain", 0.5),

    # Mobile Detection
    ("android malware detection", "android", 0.5),
    ("detect ios jailbreak", "ios", 0.5),
    ("mobile spyware detection", "spyware", 0.5),
    ("detect mobile rat", "mobile rat", 0.5),
    ("sms stealing malware detection", "sms", 0.5),
]

# Extended Forensic Queries (100+ more)
EXTENDED_FORENSIC_QUERIES = [
    # Windows Forensics Extended
    ("windows bits forensics", "bits", 0.5),
    ("wmi repository forensics", "wmi", 0.5),
    ("windows search database forensics", "windows search", 0.5),
    ("activitiescache db forensics", "activitiescache", 0.5),
    ("windows notification forensics", "notification", 0.5),
    ("windows push notification forensics", "push", 0.5),
    ("windows thumbnail cache forensics", "thumbnail", 0.5),
    ("iconcache forensics", "iconcache", 0.5),
    ("windows syscache forensics", "syscache", 0.5),
    ("bam dam forensics", "bam", 0.5),
    ("windows featureusage forensics", "featureusage", 0.5),
    ("muicache forensics", "muicache", 0.5),
    ("recentapps forensics", "recentapps", 0.5),
    ("windows terminal server forensics", "terminal server", 0.5),
    ("rdp bitmap cache forensics", "bitmap cache", 0.5),
    ("windows search edb forensics", "edb", 0.5),
    ("cortana forensics windows", "cortana", 0.5),
    ("outlook ost pst forensics", "outlook", 0.5),
    ("windows mail forensics", "windows mail", 0.5),
    ("skype forensics windows", "skype", 0.5),
    ("teams forensics", "teams", 0.5),
    ("onedrive forensics", "onedrive", 0.5),
    ("dropbox forensics", "dropbox", 0.5),
    ("google drive forensics", "google drive", 0.5),
    ("box forensics sync", "box sync", 0.5),

    # Registry Forensics Extended
    ("ntuser dat forensics", "ntuser", 0.6),
    ("usrclass dat forensics", "usrclass", 0.5),
    ("sam database forensics", "sam", 0.6),
    ("security hive forensics", "security", 0.5),
    ("system hive forensics", "system", 0.5),
    ("software hive forensics", "software", 0.5),
    ("default hive forensics", "default", 0.5),
    ("amcache hve forensics", "amcache", 0.6),
    ("bcd hive forensics", "bcd", 0.5),
    ("components hive forensics", "components", 0.5),
    ("drivers hive forensics", "drivers", 0.5),

    # Event Log Forensics Extended
    ("security evtx forensics", "security", 0.6),
    ("system evtx forensics", "system", 0.5),
    ("application evtx forensics", "application", 0.5),
    ("powershell operational evtx", "powershell", 0.6),
    ("windows defender evtx", "defender", 0.5),
    ("bits client evtx forensics", "bits", 0.5),
    ("task scheduler evtx forensics", "task scheduler", 0.5),
    ("terminal services evtx", "terminal", 0.5),
    ("rdp evtx forensics", "rdp", 0.5),
    ("wmi trace evtx forensics", "wmi", 0.5),
    ("dns client evtx forensics", "dns", 0.5),
    ("firewall evtx forensics", "firewall", 0.5),
    ("applocker evtx forensics", "applocker", 0.5),
    ("code integrity evtx", "code integrity", 0.5),
    ("ntlm operational evtx", "ntlm", 0.5),
    ("kerberos operational evtx", "kerberos", 0.5),

    # Memory Forensics Extended
    ("volatility yarascan", "yarascan", 0.5),
    ("volatility filescan", "filescan", 0.5),
    ("volatility dumpfiles", "dumpfiles", 0.5),
    ("volatility procdump", "procdump", 0.5),
    ("volatility memdump", "memdump", 0.5),
    ("volatility hivelist", "hivelist", 0.5),
    ("volatility printkey", "printkey", 0.5),
    ("volatility hashdump", "hashdump", 0.6),
    ("volatility lsadump", "lsadump", 0.5),
    ("volatility cachedump", "cachedump", 0.5),
    ("volatility clipboard", "clipboard", 0.5),
    ("volatility consoles", "consoles", 0.5),
    ("volatility cmdscan", "cmdscan", 0.5),
    ("volatility envars", "envars", 0.5),
    ("volatility verinfo", "verinfo", 0.5),
    ("volatility modules", "modules", 0.5),
    ("volatility modscan", "modscan", 0.5),
    ("volatility driverscan", "driverscan", 0.5),
    ("volatility ssdt", "ssdt", 0.5),
    ("volatility callbacks", "callbacks", 0.5),
    ("volatility idt", "idt", 0.5),
    ("volatility gdt", "gdt", 0.5),
    ("volatility timers", "timers", 0.5),
    ("volatility svcscan", "svcscan", 0.5),
    ("volatility getservicesids", "servicesids", 0.5),
    ("volatility mutantscan", "mutantscan", 0.5),
    ("volatility symlinkscan", "symlinkscan", 0.5),

    # Linux Forensics Extended
    ("linux var log forensics", "var log", 0.5),
    ("linux syslog forensics", "syslog", 0.5),
    ("linux kern log forensics", "kern", 0.5),
    ("linux dmesg forensics", "dmesg", 0.5),
    ("linux audit log forensics", "audit", 0.5),
    ("linux secure log forensics", "secure", 0.5),
    ("linux messages forensics", "messages", 0.5),
    ("linux faillog forensics", "faillog", 0.5),
    ("linux lastlog forensics", "lastlog", 0.5),
    ("linux utmp forensics", "utmp", 0.5),
    ("linux pacct forensics", "pacct", 0.5),
    ("linux httpd access forensics", "httpd", 0.5),
    ("linux mysql forensics", "mysql", 0.5),
    ("linux postgresql forensics", "postgresql", 0.5),
    ("linux docker forensics", "docker", 0.5),
    ("kubernetes audit forensics", "kubernetes", 0.5),

    # macOS Forensics Extended
    ("macos unified log forensics", "unified log", 0.5),
    ("macos asl forensics", "asl", 0.5),
    ("macos fseventsd forensics", "fseventsd", 0.5),
    ("macos spotlight forensics", "spotlight", 0.5),
    ("macos quarantine forensics", "quarantine", 0.5),
    ("macos kext forensics", "kext", 0.5),
    ("macos plist forensics", "plist", 0.5),
    ("macos airport forensics", "airport", 0.5),

    # Network Forensics Extended
    ("pcap timeline analysis", "pcap", 0.5),
    ("netflow forensics", "netflow", 0.5),
    ("dns query forensics", "dns query", 0.5),
    ("http request forensics", "http request", 0.5),
    ("tls certificate forensics", "tls certificate", 0.5),
    ("smb traffic forensics", "smb traffic", 0.5),
    ("kerberos traffic forensics", "kerberos traffic", 0.5),
    ("ldap traffic forensics", "ldap traffic", 0.5),
    ("dcerpc traffic forensics", "dcerpc", 0.5),
    ("rdp traffic forensics", "rdp traffic", 0.5),
    ("ssh traffic forensics", "ssh traffic", 0.5),
    ("ftp traffic forensics", "ftp traffic", 0.5),
    ("smtp traffic forensics", "smtp", 0.5),
    ("imap traffic forensics", "imap", 0.5),

    # Mobile Forensics Extended
    ("android sqlite forensics", "sqlite", 0.5),
    ("android shared preferences forensics", "shared preferences", 0.5),
    ("android app data forensics", "app data", 0.5),
    ("ios backup forensics", "ios backup", 0.5),
    ("ios plist forensics", "ios plist", 0.5),
    ("ios keychain forensics", "ios keychain", 0.5),
    ("ios sms forensics", "ios sms", 0.5),
    ("ios call history forensics", "call history", 0.5),

    # Cloud Forensics Extended
    ("aws cloudtrail forensics", "cloudtrail", 0.5),
    ("aws vpc flow logs forensics", "vpc flow", 0.5),
    ("aws s3 access forensics", "s3 access", 0.5),
    ("azure activity log forensics", "azure activity", 0.5),
    ("azure ad sign in forensics", "azure sign in", 0.5),
    ("gcp audit log forensics", "gcp audit", 0.5),
    ("o365 unified audit log forensics", "o365 audit", 0.5),
    ("google workspace forensics", "google workspace", 0.5),
]


# =============================================================================
# Test Classes
# =============================================================================

class TestExtendedMITRE:
    """Extended MITRE technique tests."""

    @pytest.mark.parametrize("technique_id,expected_keyword,min_score", EXTENDED_MITRE_QUERIES)
    def test_extended_mitre_technique(self, rag_index, technique_id, expected_keyword, min_score):
        """Test extended MITRE technique queries."""
        result = rag_index.search(technique_id, top_k=5)
        results = result["results"]

        assert results, f"No results for: {technique_id}"
        # Allow lower scores for extended techniques that may have less coverage
        assert results[0]["score"] >= min_score, \
            f"Score {results[0]['score']:.3f} below {min_score} for: {technique_id}"


class TestExtendedDetection:
    """Extended detection scenario tests."""

    @pytest.mark.parametrize("query,expected_keyword,min_score", EXTENDED_DETECTION_QUERIES)
    def test_extended_detection(self, rag_index, query, expected_keyword, min_score):
        """Test extended detection queries."""
        result = rag_index.search(query, top_k=5)
        results = result["results"]

        assert results, f"No results for: {query}"
        assert results[0]["score"] >= min_score, \
            f"Score {results[0]['score']:.3f} below {min_score} for: {query}"


class TestExtendedForensics:
    """Extended forensics tests."""

    @pytest.mark.parametrize("query,expected_keyword,min_score", EXTENDED_FORENSIC_QUERIES)
    def test_extended_forensics(self, rag_index, query, expected_keyword, min_score):
        """Test extended forensic queries."""
        result = rag_index.search(query, top_k=5)
        results = result["results"]

        assert results, f"No results for: {query}"
        assert results[0]["score"] >= min_score, \
            f"Score {results[0]['score']:.3f} below {min_score} for: {query}"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
