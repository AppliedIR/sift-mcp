"""Pytest fixtures for forensic triage tests."""

import sqlite3
import tempfile
from pathlib import Path

import pytest

from windows_triage.db.schemas import KNOWN_GOOD_SCHEMA, CONTEXT_SCHEMA, REGISTRY_FULL_SCHEMA


@pytest.fixture
def temp_known_good_db():
    """Create a temporary known_good.db for testing (v2 schema)."""
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        db_path = Path(f.name)

    conn = sqlite3.connect(db_path)
    conn.executescript(KNOWN_GOOD_SCHEMA)

    # Insert some test data
    cursor = conn.cursor()

    # First insert an OS version (v2 schema uses short_name)
    cursor.execute("""
        INSERT INTO baseline_os (short_name, os_family, os_edition, os_release)
        VALUES (?, ?, ?, ?)
    """, ('W10_21H2_Enterprise_20220101', 'Windows 10', 'Enterprise', '21H2'))
    os_id = cursor.lastrowid
    os_name = 'W10_21H2_Enterprise_20220101'

    # Baseline files (v2 schema - path deduplication with JSON os_versions)
    test_files = [
        ('\\windows\\system32\\cmd.exe', '\\windows\\system32', 'cmd.exe', 'abc123' + '0' * 26, 'def456' + '0' * 34, 'a' * 64),
        ('\\windows\\system32\\notepad.exe', '\\windows\\system32', 'notepad.exe', 'aaa111' + '0' * 26, 'bbb222' + '0' * 34, 'b' * 64),
        ('\\windows\\system32\\svchost.exe', '\\windows\\system32', 'svchost.exe', 'svc111' + '0' * 26, 'svc222' + '0' * 34, 'c' * 64),
        ('\\windows\\explorer.exe', '\\windows', 'explorer.exe', 'exp111' + '0' * 26, 'exp222' + '0' * 34, 'd' * 64),
        ('\\windows\\system32\\certutil.exe', '\\windows\\system32', 'certutil.exe', 'cert11' + '0' * 26, 'cert22' + '0' * 34, 'e' * 64),
    ]

    import json
    for path, directory, name, md5, sha1, sha256 in test_files:
        # Insert file with os_versions as JSON array
        cursor.execute("""
            INSERT INTO baseline_files (path_normalized, directory_normalized, filename_lower, os_versions, first_seen_source)
            VALUES (?, ?, ?, ?, ?)
        """, (path, directory, name, json.dumps([os_name]), 'test'))
        file_id = cursor.lastrowid

        # Insert hashes into baseline_hashes
        cursor.execute("""
            INSERT INTO baseline_hashes (hash_value, hash_type, file_id, os_id)
            VALUES (?, ?, ?, ?)
        """, (md5, 'md5', file_id, os_id))
        cursor.execute("""
            INSERT INTO baseline_hashes (hash_value, hash_type, file_id, os_id)
            VALUES (?, ?, ?, ?)
        """, (sha1, 'sha1', file_id, os_id))
        cursor.execute("""
            INSERT INTO baseline_hashes (hash_value, hash_type, file_id, os_id)
            VALUES (?, ?, ?, ?)
        """, (sha256, 'sha256', file_id, os_id))

    conn.commit()
    conn.close()

    yield db_path

    # Cleanup
    db_path.unlink(missing_ok=True)


@pytest.fixture
def temp_context_db():
    """Create a temporary context.db for testing."""
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        db_path = Path(f.name)

    conn = sqlite3.connect(db_path)
    conn.executescript(CONTEXT_SCHEMA)

    cursor = conn.cursor()

    # LOLBins - use actual schema column names
    cursor.execute("""
        INSERT INTO lolbins (filename_lower, name, description, expected_paths, functions, mitre_techniques)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        'certutil.exe', 'Certutil.exe', 'Certificate utility',
        '["\\\\windows\\\\system32\\\\certutil.exe"]',
        '["Download", "Execute", "Encode"]',
        '["T1105", "T1140"]'
    ))

    cursor.execute("""
        INSERT INTO lolbins (filename_lower, name, description, expected_paths, functions, mitre_techniques)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        'mshta.exe', 'Mshta.exe', 'Microsoft HTML Application Host',
        '["\\\\windows\\\\system32\\\\mshta.exe"]',
        '["Execute"]',
        '["T1218.005"]'
    ))

    # Vulnerable drivers - use actual schema column names including authentihash
    cursor.execute("""
        INSERT INTO vulnerable_drivers (
            filename_lower, sha256, sha1, md5,
            authentihash_sha256, authentihash_sha1, authentihash_md5,
            vendor, product, cve, description
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        'vulndriver.sys',
        'aabbccdd1234567890abcdef1234567890abcdef1234567890abcdef12345678',  # sha256
        'aabbccdd1234567890abcdef1234567890123456',  # sha1
        'aabbccdd1234567890abcdef12345678',  # md5
        'authccdd1234567890abcdef1234567890abcdef1234567890abcdef12345678',  # authentihash_sha256
        'authccdd1234567890abcdef1234567890123456',  # authentihash_sha1
        'authccdd1234567890abcdef12345678',  # authentihash_md5
        'Test Vendor',
        'VulnDriver.sys',
        'CVE-2021-1234',
        'Test vulnerable driver'
    ))

    # Hijackable DLLs - use actual schema column names
    cursor.execute("""
        INSERT INTO hijackable_dlls (dll_name_lower, hijack_type, vulnerable_exe, vulnerable_exe_path)
        VALUES (?, ?, ?, ?)
    """, ('version.dll', 'Sideloading', 'notepad.exe', '\\windows\\system32\\notepad.exe'))

    # Process expectations
    cursor.execute("""
        INSERT INTO expected_processes (process_name_lower, valid_parents, parent_exits, valid_paths, user_type, source)
        VALUES (?, ?, ?, ?, ?, ?)
    """, ('svchost.exe', '["services.exe"]', 0, '["\\\\windows\\\\system32\\\\svchost.exe"]', 'EITHER', 'test'))

    cursor.execute("""
        INSERT INTO expected_processes (process_name_lower, valid_parents, parent_exits, valid_paths, user_type, source)
        VALUES (?, ?, ?, ?, ?, ?)
    """, ('lsass.exe', '["wininit.exe"]', 0, '["\\\\windows\\\\system32\\\\lsass.exe"]', 'SYSTEM', 'test'))

    cursor.execute("""
        INSERT INTO expected_processes (process_name_lower, valid_parents, parent_exits, valid_paths, user_type, source)
        VALUES (?, ?, ?, ?, ?, ?)
    """, ('cmd.exe', '[]', 0, '["\\\\windows\\\\system32\\\\cmd.exe"]', 'USER', 'test'))

    # Suspicious filenames - use actual schema column names
    cursor.execute("""
        INSERT INTO suspicious_filenames (filename_pattern, is_regex, category, tool_name, risk_level)
        VALUES (?, ?, ?, ?, ?)
    """, ('mimikatz.exe', 0, 'credential_theft', 'Mimikatz', 'critical'))

    cursor.execute("""
        INSERT INTO suspicious_filenames (filename_pattern, is_regex, category, tool_name, risk_level)
        VALUES (?, ?, ?, ?, ?)
    """, ('^psexec.*\\.exe$', 1, 'lateral_movement', 'PsExec', 'high'))

    # Protected process names - use actual schema column names
    cursor.execute("""
        INSERT INTO protected_process_names (process_name_lower, canonical_form, description)
        VALUES (?, ?, ?)
    """, ('svchost.exe', 'svchost.exe', 'Service Host'))

    cursor.execute("""
        INSERT INTO protected_process_names (process_name_lower, canonical_form, description)
        VALUES (?, ?, ?)
    """, ('lsass.exe', 'lsass.exe', 'Local Security Authority'))

    cursor.execute("""
        INSERT INTO protected_process_names (process_name_lower, canonical_form, description)
        VALUES (?, ?, ?)
    """, ('csrss.exe', 'csrss.exe', 'Client Server Runtime'))

    # Suspicious pipe patterns
    suspicious_pipes = [
        ('msagent_*', 1, 'cobalt_strike', 'Default Cobalt Strike pipe pattern'),
        ('MSSE-*', 1, 'cobalt_strike', 'Cobalt Strike SMB beacon variant'),
        ('postex_*', 1, 'cobalt_strike', 'Cobalt Strike post-exploitation'),
        ('status_*', 1, 'cobalt_strike', 'Cobalt Strike status pipe'),
        ('meterpreter', 0, 'metasploit', 'Metasploit named pipe'),
        ('psexecsvc', 0, 'psexec', 'PsExec service pipe'),
    ]
    for pattern, is_regex, tool_name, description in suspicious_pipes:
        cursor.execute("""
            INSERT INTO suspicious_pipe_patterns (pipe_pattern, is_regex, tool_name, description)
            VALUES (?, ?, ?, ?)
        """, (pattern, is_regex, tool_name, description))

    # Windows named pipes
    windows_pipes = [
        ('lsass', 'LSASS', 'Local Security Authority', 'LSA main pipe'),
        ('lsarpc', 'RPC', 'LSA Remote Protocol', 'MS-LSAD'),
        ('samr', 'RPC', 'SAM Remote Protocol', 'MS-SAMR'),
        ('netlogon', 'RPC', 'Netlogon Remote Protocol', 'MS-NRPC'),
        ('srvsvc', 'RPC', 'Server Service', 'MS-SRVS'),
        ('wkssvc', 'RPC', 'Workstation Service', 'MS-WKST'),
        ('svcctl', 'RPC', 'Service Control Manager', 'MS-SCMR'),
        ('eventlog', 'RPC', 'EventLog Remoting Protocol', 'MS-EVEN'),
        ('winreg', 'RPC', 'Windows Remote Registry', 'MS-RRP'),
        ('spoolss', 'RPC', 'Print Spooler', 'MS-RPRN'),
    ]
    for pipe_name, protocol, service_name, description in windows_pipes:
        cursor.execute("""
            INSERT INTO windows_named_pipes (pipe_name, protocol, service_name, description)
            VALUES (?, ?, ?, ?)
        """, (pipe_name, protocol, service_name, description))

    conn.commit()
    conn.close()

    yield db_path

    # Cleanup
    db_path.unlink(missing_ok=True)


@pytest.fixture
def known_good_db_instance(temp_known_good_db):
    """Create a KnownGoodDB instance for testing."""
    from windows_triage.db.known_good import KnownGoodDB
    # Use read_only=False for tests (need to write test data), cache_size=0 for deterministic tests
    db = KnownGoodDB(temp_known_good_db, read_only=False, cache_size=0)
    yield db
    db.close()


@pytest.fixture
def context_db_instance(temp_context_db):
    """Create a ContextDB instance for testing."""
    from windows_triage.db.context import ContextDB
    # Use read_only=False for tests, cache_size=0 for deterministic tests
    db = ContextDB(temp_context_db, read_only=False, cache_size=0)
    yield db
    db.close()


@pytest.fixture
def temp_registry_db():
    """Create a temporary registry database with test data."""
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        db_path = Path(f.name)

    conn = sqlite3.connect(db_path)
    conn.executescript(REGISTRY_FULL_SCHEMA)

    cursor = conn.cursor()

    # Insert OS versions
    cursor.execute("""
        INSERT INTO baseline_os (short_name, os_family, os_edition, os_release)
        VALUES (?, ?, ?, ?)
    """, ('W11_22H2', 'Windows 11', 'Enterprise', '22H2'))

    cursor.execute("""
        INSERT INTO baseline_os (short_name, os_family, os_edition, os_release)
        VALUES (?, ?, ?, ?)
    """, ('W10_21H2', 'Windows 10', 'Professional', '21H2'))

    # Insert registry entries for SOFTWARE hive
    import json
    test_entries = [
        # Run keys (common persistence location)
        ('SOFTWARE', 'microsoft\\windows\\currentversion\\run', 'SecurityHealth',
         'REG_SZ', '%ProgramFiles%\\Windows Defender\\MSASCuiL.exe', '["W11_22H2", "W10_21H2"]'),
        ('SOFTWARE', 'microsoft\\windows\\currentversion\\run', 'VMware User Process',
         'REG_SZ', '"C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe" -n vmusr', '["W10_21H2"]'),
        # Windows settings
        ('SOFTWARE', 'microsoft\\windows\\currentversion', 'ProgramFilesDir',
         'REG_SZ', 'C:\\Program Files', '["W11_22H2", "W10_21H2"]'),
        ('SOFTWARE', 'microsoft\\windows\\currentversion', 'CommonFilesDir',
         'REG_SZ', 'C:\\Program Files\\Common Files', '["W11_22H2", "W10_21H2"]'),
        # SYSTEM hive entries
        ('SYSTEM', 'currentcontrolset\\services\\bits', 'Start',
         'REG_DWORD', '3', '["W11_22H2", "W10_21H2"]'),
        ('SYSTEM', 'currentcontrolset\\services\\bits', 'Type',
         'REG_DWORD', '32', '["W11_22H2", "W10_21H2"]'),
        # NTUSER hive entries
        ('NTUSER', 'software\\microsoft\\windows\\currentversion\\run', 'OneDrive',
         'REG_SZ', '"C:\\Users\\user\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe" /background', '["W11_22H2"]'),
    ]

    for hive, key_path, value_name, value_type, value_data, os_versions in test_entries:
        cursor.execute("""
            INSERT INTO baseline_registry (hive, key_path_lower, value_name, value_type, value_data, os_versions)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (hive, key_path, value_name, value_type, value_data, os_versions))

    conn.commit()
    conn.close()

    yield db_path

    # Cleanup
    db_path.unlink(missing_ok=True)


@pytest.fixture
def registry_db_instance(temp_registry_db):
    """Create a RegistryDB instance for testing."""
    from windows_triage.db.registry import RegistryDB
    db = RegistryDB(temp_registry_db, read_only=False, cache_size=0)
    yield db
    db.close()


@pytest.fixture
def empty_temp_registry_db():
    """Create an empty temporary registry database (schema only, no data)."""
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        db_path = Path(f.name)

    conn = sqlite3.connect(db_path)
    conn.executescript(REGISTRY_FULL_SCHEMA)
    conn.commit()
    conn.close()

    yield db_path

    db_path.unlink(missing_ok=True)
