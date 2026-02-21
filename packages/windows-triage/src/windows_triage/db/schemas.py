"""
SQL Schema Definitions for Windows Triage Databases (v2)

Architecture:
    known_good.db       - Ground truth baselines (files, services, tasks, autoruns)
    context.db          - Risk enrichment (LOLBins, drivers, patterns)
    known_good_registry.db - Optional full registry baseline (separate file)

Design Decisions:
    1. Path deduplication: Each unique path stored once with os_versions JSON array
    2. Hash index: Separate table for efficient hash lookups without row multiplication
    3. Registry extractions: Services/tasks/autoruns extracted into dedicated tables
    4. Optional full registry: Separate database file for users who need it
"""

# ============================================================
# known_good.db - Ground Truth Baselines (Hybrid Schema)
# ============================================================

KNOWN_GOOD_SCHEMA = """
-- ═══════════════════════════════════════════════════════════════
-- OS VERSION REFERENCE
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS baseline_os (
    id INTEGER PRIMARY KEY,
    short_name TEXT UNIQUE NOT NULL,        -- "Win10_21H2_Pro", "Win11_22H2_Enterprise"
    os_family TEXT NOT NULL,                -- "Windows 10", "Windows 11", "Windows Server 2022"
    os_edition TEXT,                        -- "Pro", "Enterprise", "Home", "Standard"
    os_release TEXT,                        -- "21H2", "22H2"
    build_number TEXT,
    architecture TEXT DEFAULT 'x64',
    source_csv TEXT,                        -- Original CSV filename
    imported_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- ═══════════════════════════════════════════════════════════════
-- FILE BASELINES (VanillaWindowsReference)
-- Deduplicated: each unique path stored once
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS baseline_files (
    id INTEGER PRIMARY KEY,
    path_normalized TEXT UNIQUE,            -- Full path, normalized (lowercase, no drive)
    directory_normalized TEXT NOT NULL,     -- Parent directory
    filename_lower TEXT NOT NULL,           -- Filename only, lowercase
    os_versions TEXT NOT NULL,              -- JSON: ["Win10_21H2_Pro", "Win11_22H2_Enterprise"]
    first_seen_source TEXT,                 -- Which CSV first added this path
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_files_path ON baseline_files(path_normalized);
CREATE INDEX IF NOT EXISTS idx_files_filename ON baseline_files(filename_lower);
CREATE INDEX IF NOT EXISTS idx_files_directory ON baseline_files(directory_normalized);

-- ═══════════════════════════════════════════════════════════════
-- HASH INDEX (Links hashes to files)
-- Allows efficient hash lookup without row multiplication
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS baseline_hashes (
    id INTEGER PRIMARY KEY,
    hash_value TEXT NOT NULL,               -- Lowercase hash
    hash_type TEXT NOT NULL,                -- "md5", "sha1", "sha256"
    file_id INTEGER NOT NULL,               -- Reference to baseline_files
    os_id INTEGER,                          -- Which OS version had this hash (optional)
    file_size INTEGER,                      -- File size when this hash was recorded
    FOREIGN KEY (file_id) REFERENCES baseline_files(id) ON DELETE CASCADE,
    FOREIGN KEY (os_id) REFERENCES baseline_os(id) ON DELETE SET NULL,
    UNIQUE(hash_value, hash_type, file_id)
);

CREATE INDEX IF NOT EXISTS idx_hashes_value ON baseline_hashes(hash_value);
CREATE INDEX IF NOT EXISTS idx_hashes_type_value ON baseline_hashes(hash_type, hash_value);
CREATE INDEX IF NOT EXISTS idx_hashes_file ON baseline_hashes(file_id);

-- ═══════════════════════════════════════════════════════════════
-- SERVICE BASELINES (Extracted from VanillaWindowsRegistryHives)
-- Deduplicated: each unique service stored once
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS baseline_services (
    id INTEGER PRIMARY KEY,
    service_name_lower TEXT UNIQUE NOT NULL,    -- Service key name, lowercase
    display_name TEXT,                          -- DisplayName value
    binary_path_pattern TEXT,                   -- ImagePath (normalized, variables preserved)
    start_type INTEGER,                         -- 0=Boot, 1=System, 2=Auto, 3=Manual, 4=Disabled
    service_type INTEGER,                       -- 1=Kernel, 2=FileSystem, 16=OwnProcess, 32=ShareProcess
    object_name TEXT,                           -- Account/driver object
    description TEXT,
    os_versions TEXT NOT NULL,                  -- JSON array
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_services_name ON baseline_services(service_name_lower);
CREATE INDEX IF NOT EXISTS idx_services_binary ON baseline_services(binary_path_pattern);

-- ═══════════════════════════════════════════════════════════════
-- SCHEDULED TASK BASELINES (Extracted from VanillaWindowsRegistryHives)
-- Deduplicated: each unique task stored once
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS baseline_tasks (
    id INTEGER PRIMARY KEY,
    task_path_lower TEXT UNIQUE NOT NULL,       -- Full task path, lowercase
    task_name TEXT,                             -- Task name (display)
    uri TEXT,                                   -- Task URI from registry
    actions_summary TEXT,                       -- JSON summary of actions
    triggers_summary TEXT,                      -- JSON summary of triggers
    author TEXT,
    os_versions TEXT NOT NULL,                  -- JSON array
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_tasks_path ON baseline_tasks(task_path_lower);
CREATE INDEX IF NOT EXISTS idx_tasks_name ON baseline_tasks(task_name);

-- ═══════════════════════════════════════════════════════════════
-- AUTORUN BASELINES (Extracted from VanillaWindowsRegistryHives)
-- Deduplicated: each unique autorun entry stored once
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS baseline_autoruns (
    id INTEGER PRIMARY KEY,
    hive TEXT NOT NULL,                         -- "HKLM" or "HKU"
    key_path_lower TEXT NOT NULL,               -- Registry key path, lowercase
    value_name TEXT,                            -- Value name (NULL for default)
    value_data_pattern TEXT,                    -- Value data (command/path pattern)
    autorun_type TEXT,                          -- "Run", "RunOnce", "Services", etc.
    os_versions TEXT NOT NULL,                  -- JSON array
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(hive, key_path_lower, value_name)
);

CREATE INDEX IF NOT EXISTS idx_autoruns_key ON baseline_autoruns(key_path_lower);
CREATE INDEX IF NOT EXISTS idx_autoruns_type ON baseline_autoruns(autorun_type);

-- ═══════════════════════════════════════════════════════════════
-- SYNC TRACKING
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS sources (
    name TEXT PRIMARY KEY,
    source_type TEXT NOT NULL,                  -- "git", "manual"
    url TEXT,
    last_sync_time TEXT,
    last_sync_commit TEXT,
    record_count INTEGER DEFAULT 0,
    notes TEXT
);

INSERT OR IGNORE INTO sources (name, source_type, url, notes) VALUES
    ('vanilla_windows_reference', 'git', 'https://github.com/AndrewRathbun/VanillaWindowsReference',
     'File baselines from clean Windows installations'),
    ('vanilla_windows_registry', 'git', 'https://github.com/AndrewRathbun/VanillaWindowsRegistryHives',
     'Registry exports for services, tasks, autoruns extraction');
"""


# ============================================================
# known_good_registry.db - Optional Full Registry Baseline
# ============================================================

REGISTRY_FULL_SCHEMA = """
-- ═══════════════════════════════════════════════════════════════
-- FULL REGISTRY BASELINE (Optional - separate database)
-- For users who need to validate arbitrary registry keys
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS baseline_os (
    id INTEGER PRIMARY KEY,
    short_name TEXT UNIQUE NOT NULL,
    os_family TEXT NOT NULL,
    os_edition TEXT,
    os_release TEXT,
    build_number TEXT,
    architecture TEXT DEFAULT 'x64',
    source_json TEXT,
    imported_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS baseline_registry (
    id INTEGER PRIMARY KEY,
    hive TEXT NOT NULL,                         -- "SYSTEM", "SOFTWARE", "NTUSER", "DEFAULT"
    key_path_lower TEXT NOT NULL,               -- Full key path, normalized lowercase
    value_name TEXT,                            -- Value name (NULL for key-only or default)
    value_type TEXT,                            -- "REG_SZ", "REG_DWORD", "REG_BINARY", etc.
    value_data TEXT,                            -- Actual value (strings/ints as text, binary as hex)
    value_data_hash TEXT,                       -- SHA256 of value_data for dedup comparison
    os_versions TEXT NOT NULL,                  -- JSON array
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(hive, key_path_lower, value_name, value_data_hash)
);

CREATE INDEX IF NOT EXISTS idx_registry_hive_key ON baseline_registry(hive, key_path_lower);
CREATE INDEX IF NOT EXISTS idx_registry_key ON baseline_registry(key_path_lower);
CREATE INDEX IF NOT EXISTS idx_registry_value_name ON baseline_registry(value_name);

CREATE TABLE IF NOT EXISTS sources (
    name TEXT PRIMARY KEY,
    source_type TEXT NOT NULL,
    url TEXT,
    last_sync_time TEXT,
    last_sync_commit TEXT,
    record_count INTEGER DEFAULT 0
);

INSERT OR IGNORE INTO sources (name, source_type, url) VALUES
    ('vanilla_windows_registry', 'git', 'https://github.com/AndrewRathbun/VanillaWindowsRegistryHives');
"""


# ============================================================
# context.db - Risk Enrichment (unchanged from v1)
# ============================================================

CONTEXT_SCHEMA = """
-- LOLBINS (LOLBAS Project)
CREATE TABLE IF NOT EXISTS lolbins (
    id INTEGER PRIMARY KEY,
    filename_lower TEXT NOT NULL UNIQUE,
    name TEXT,
    description TEXT,
    functions TEXT,           -- JSON array
    expected_paths TEXT,      -- JSON array
    mitre_techniques TEXT,    -- JSON array
    detection TEXT,
    source_url TEXT
);

CREATE INDEX IF NOT EXISTS idx_lol_filename ON lolbins(filename_lower);

-- HIJACKABLE DLLS (HijackLibs)
CREATE TABLE IF NOT EXISTS hijackable_dlls (
    id INTEGER PRIMARY KEY,
    dll_name_lower TEXT NOT NULL,
    hijack_type TEXT,
    vulnerable_exe TEXT,
    vulnerable_exe_path TEXT,
    expected_paths TEXT,      -- JSON array
    vendor TEXT,
    UNIQUE(dll_name_lower, vulnerable_exe)
);

CREATE INDEX IF NOT EXISTS idx_hjk_dll ON hijackable_dlls(dll_name_lower);

-- VULNERABLE DRIVERS (LOLDrivers - vulnerable category only)
CREATE TABLE IF NOT EXISTS vulnerable_drivers (
    id INTEGER PRIMARY KEY,
    filename_lower TEXT,
    sha256 TEXT,
    sha1 TEXT,
    md5 TEXT,
    authentihash_sha256 TEXT,
    authentihash_sha1 TEXT,
    authentihash_md5 TEXT,
    vendor TEXT,
    product TEXT,
    cve TEXT,
    vulnerability_type TEXT,
    description TEXT
);

CREATE INDEX IF NOT EXISTS idx_vd_sha256 ON vulnerable_drivers(sha256) WHERE sha256 IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_vd_sha1 ON vulnerable_drivers(sha1) WHERE sha1 IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_vd_md5 ON vulnerable_drivers(md5) WHERE md5 IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_vd_auth_sha256 ON vulnerable_drivers(authentihash_sha256) WHERE authentihash_sha256 IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_vd_auth_sha1 ON vulnerable_drivers(authentihash_sha1) WHERE authentihash_sha1 IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_vd_auth_md5 ON vulnerable_drivers(authentihash_md5) WHERE authentihash_md5 IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_vd_filename ON vulnerable_drivers(filename_lower);

-- EXPECTED PROCESSES (from YAML - sourced from MemProcFS + SANS Hunt Evil)
CREATE TABLE IF NOT EXISTS expected_processes (
    id INTEGER PRIMARY KEY,
    process_name_lower TEXT NOT NULL UNIQUE,
    valid_parents TEXT,               -- JSON array (null = any parent allowed)
    suspicious_parents TEXT,          -- JSON array (parents that indicate attack)
    never_spawns_children INTEGER DEFAULT 0,  -- If 1, this process should NEVER be a parent
    parent_exits INTEGER DEFAULT 0,
    valid_paths TEXT,                 -- JSON array
    user_type TEXT,                   -- SYSTEM, USER, EITHER
    valid_users TEXT,                 -- JSON array
    min_instances INTEGER DEFAULT 1,
    max_instances INTEGER,
    per_session INTEGER DEFAULT 0,
    required_args TEXT,
    source TEXT
);

CREATE INDEX IF NOT EXISTS idx_ep_name ON expected_processes(process_name_lower);

-- WINDOWS NAMED PIPES (Microsoft-documented)
CREATE TABLE IF NOT EXISTS windows_named_pipes (
    id INTEGER PRIMARY KEY,
    pipe_name TEXT NOT NULL UNIQUE,
    pipe_pattern TEXT,
    protocol TEXT,
    service_name TEXT,
    associated_process TEXT,
    microsoft_doc_url TEXT,
    description TEXT
);

CREATE INDEX IF NOT EXISTS idx_np_name ON windows_named_pipes(pipe_name);

-- SUSPICIOUS FILENAME PATTERNS (risk indicators)
CREATE TABLE IF NOT EXISTS suspicious_filenames (
    id INTEGER PRIMARY KEY,
    filename_pattern TEXT NOT NULL UNIQUE,
    is_regex INTEGER DEFAULT 0,
    tool_name TEXT,
    category TEXT,
    mitre_techniques TEXT,
    risk_level TEXT DEFAULT 'high',
    notes TEXT
);

CREATE INDEX IF NOT EXISTS idx_sf_pattern ON suspicious_filenames(filename_pattern);

-- SUSPICIOUS PIPE PATTERNS (C2 indicators)
CREATE TABLE IF NOT EXISTS suspicious_pipe_patterns (
    id INTEGER PRIMARY KEY,
    pipe_pattern TEXT NOT NULL UNIQUE,
    is_regex INTEGER DEFAULT 0,
    pipe_example TEXT,
    tool_name TEXT,
    malware_family TEXT,
    mitre_technique TEXT,
    description TEXT
);

-- PROTECTED PROCESS NAMES (for homoglyph detection)
CREATE TABLE IF NOT EXISTS protected_process_names (
    id INTEGER PRIMARY KEY,
    process_name_lower TEXT NOT NULL UNIQUE,
    canonical_form TEXT NOT NULL,
    description TEXT
);

-- SYNC TRACKING
CREATE TABLE IF NOT EXISTS sources (
    name TEXT PRIMARY KEY,
    source_type TEXT NOT NULL,
    url TEXT,
    last_sync_time TEXT,
    last_sync_commit TEXT,
    record_count INTEGER DEFAULT 0
);

INSERT OR IGNORE INTO sources (name, source_type, url) VALUES
    ('lolbas', 'git', 'https://github.com/LOLBAS-Project/LOLBAS'),
    ('hijacklibs', 'git', 'https://github.com/wietze/HijackLibs'),
    ('loldrivers_vulnerable', 'git', 'https://github.com/magicsword-io/LOLDrivers'),
    ('process_expectations', 'yaml', 'data/process_expectations.yaml'),
    ('named_pipes', 'manual', 'https://learn.microsoft.com');
"""


# ============================================================
# Initial data for context.db (unchanged from v1)
# ============================================================

CONTEXT_INITIAL_DATA = """
-- Pre-populate common tool filenames
INSERT OR IGNORE INTO suspicious_filenames (filename_pattern, tool_name, category, risk_level) VALUES
    ('mimikatz.exe', 'mimikatz', 'credential_theft', 'critical'),
    ('mimi.exe', 'mimikatz', 'credential_theft', 'critical'),
    ('mimi32.exe', 'mimikatz', 'credential_theft', 'critical'),
    ('mimi64.exe', 'mimikatz', 'credential_theft', 'critical'),
    ('sekurlsa.exe', 'mimikatz', 'credential_theft', 'critical'),
    ('beacon.exe', 'cobalt_strike', 'c2', 'critical'),
    ('beacon.dll', 'cobalt_strike', 'c2', 'critical'),
    ('rubeus.exe', 'rubeus', 'credential_theft', 'critical'),
    ('seatbelt.exe', 'seatbelt', 'recon', 'high'),
    ('sharpup.exe', 'sharpup', 'privesc', 'high'),
    ('sharphound.exe', 'bloodhound', 'recon', 'high'),
    ('bloodhound.exe', 'bloodhound', 'recon', 'high'),
    ('lazagne.exe', 'lazagne', 'credential_theft', 'critical'),
    ('procdump.exe', 'sysinternals', 'credential_theft', 'medium'),
    ('procdump64.exe', 'sysinternals', 'credential_theft', 'medium'),
    ('psexec.exe', 'sysinternals', 'lateral_movement', 'medium'),
    ('psexesvc.exe', 'sysinternals', 'lateral_movement', 'medium'),
    ('winpeas.exe', 'winpeas', 'privesc', 'high'),
    ('linpeas.sh', 'linpeas', 'privesc', 'high'),
    ('nc.exe', 'netcat', 'backdoor', 'high'),
    ('ncat.exe', 'ncat', 'backdoor', 'high'),
    ('chisel.exe', 'chisel', 'tunneling', 'high'),
    ('plink.exe', 'plink', 'tunneling', 'medium'),
    ('rclone.exe', 'rclone', 'exfiltration', 'medium'),
    ('kerberoast.exe', 'kerberoast', 'credential_theft', 'critical'),
    ('kerbrute.exe', 'kerbrute', 'credential_theft', 'high'),
    ('impacket', 'impacket', 'credential_theft', 'high');

-- Pre-populate suspicious pipe patterns
INSERT OR IGNORE INTO suspicious_pipe_patterns (pipe_pattern, is_regex, tool_name, description) VALUES
    ('msagent_*', 1, 'cobalt_strike', 'Default Cobalt Strike pipe pattern'),
    ('MSSE-*', 1, 'cobalt_strike', 'Cobalt Strike SMB beacon variant'),
    ('postex_*', 1, 'cobalt_strike', 'Cobalt Strike post-exploitation'),
    ('status_*', 1, 'cobalt_strike', 'Cobalt Strike status pipe'),
    ('meterpreter', 0, 'metasploit', 'Metasploit named pipe'),
    ('psexecsvc', 0, 'psexec', 'PsExec service pipe'),
    ('winsock', 0, 'metasploit', 'Common Metasploit pipe'),
    ('ntsvcs_*', 1, 'cobalt_strike', 'Cobalt Strike variant');

-- Pre-populate protected process names (for homoglyph/typosquatting detection)
-- These are critical Windows processes commonly targeted for name spoofing
INSERT OR IGNORE INTO protected_process_names (process_name_lower, canonical_form, description) VALUES
    -- Core system processes
    ('svchost.exe', 'svchost.exe', 'Service Host'),
    ('csrss.exe', 'csrss.exe', 'Client Server Runtime'),
    ('lsass.exe', 'lsass.exe', 'Local Security Authority'),
    ('services.exe', 'services.exe', 'Service Control Manager'),
    ('smss.exe', 'smss.exe', 'Session Manager'),
    ('wininit.exe', 'wininit.exe', 'Windows Initialization'),
    ('winlogon.exe', 'winlogon.exe', 'Windows Logon'),
    ('explorer.exe', 'explorer.exe', 'Windows Explorer'),
    ('dwm.exe', 'dwm.exe', 'Desktop Window Manager'),
    ('conhost.exe', 'conhost.exe', 'Console Window Host'),
    ('dllhost.exe', 'dllhost.exe', 'COM Surrogate'),
    -- Task and service hosts
    ('taskhostw.exe', 'taskhostw.exe', 'Task Host Window'),
    ('taskhost.exe', 'taskhost.exe', 'Task Host'),
    ('runtimebroker.exe', 'runtimebroker.exe', 'Runtime Broker'),
    ('sihost.exe', 'sihost.exe', 'Shell Infrastructure Host'),
    -- System services
    ('spoolsv.exe', 'spoolsv.exe', 'Print Spooler'),
    ('lsm.exe', 'lsm.exe', 'Local Session Manager'),
    ('searchindexer.exe', 'searchindexer.exe', 'Windows Search Indexer'),
    ('wmiprvse.exe', 'wmiprvse.exe', 'WMI Provider Host'),
    -- Security processes
    ('lsaiso.exe', 'lsaiso.exe', 'LSA Isolated'),
    ('msmpeng.exe', 'msmpeng.exe', 'Windows Defender Antimalware'),
    ('securityhealthservice.exe', 'securityhealthservice.exe', 'Windows Security Health'),
    -- User interface
    ('fontdrvhost.exe', 'fontdrvhost.exe', 'Font Driver Host'),
    ('ctfmon.exe', 'ctfmon.exe', 'CTF Loader'),
    ('audiodg.exe', 'audiodg.exe', 'Audio Device Graph Isolation'),
    ('logonui.exe', 'logonui.exe', 'Logon User Interface'),
    -- PowerShell (common target)
    ('powershell.exe', 'powershell.exe', 'Windows PowerShell'),
    ('pwsh.exe', 'pwsh.exe', 'PowerShell Core'),
    -- Command prompt
    ('cmd.exe', 'cmd.exe', 'Command Prompt');

-- Pre-populate Windows named pipes (Microsoft-documented)
INSERT OR IGNORE INTO windows_named_pipes (pipe_name, protocol, service_name, description) VALUES
    ('lsass', 'LSASS', 'Local Security Authority', 'LSA main pipe'),
    ('lsarpc', 'RPC', 'LSA Remote Protocol', 'MS-LSAD'),
    ('samr', 'RPC', 'SAM Remote Protocol', 'MS-SAMR'),
    ('netlogon', 'RPC', 'Netlogon Remote Protocol', 'MS-NRPC'),
    ('srvsvc', 'RPC', 'Server Service', 'MS-SRVS'),
    ('wkssvc', 'RPC', 'Workstation Service', 'MS-WKST'),
    ('svcctl', 'RPC', 'Service Control Manager', 'MS-SCMR'),
    ('eventlog', 'RPC', 'EventLog Remoting Protocol', 'MS-EVEN'),
    ('winreg', 'RPC', 'Windows Remote Registry', 'MS-RRP'),
    ('atsvc', 'RPC', 'Task Scheduler (AT)', 'MS-TSCH'),
    ('spoolss', 'RPC', 'Print Spooler', 'MS-RPRN'),
    ('browser', 'SMB', 'Computer Browser', 'MS-BRWS'),
    ('epmapper', 'RPC', 'Endpoint Mapper', 'MS-RPCE'),
    ('ntsvcs', 'RPC', 'Plug and Play', 'MS-PNP'),
    ('scerpc', 'RPC', 'Security Configuration', 'MS-SCMP'),
    ('dnsserver', 'RPC', 'DNS Server', 'MS-DNSP'),
    ('iisrpc', 'RPC', 'IIS Administration', 'IIS'),
    ('protected_storage', 'RPC', 'Protected Storage', 'DPAPI');
"""
