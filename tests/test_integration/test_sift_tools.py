"""Integration tests for sift-mcp: real forensic tools on real evidence.

Layer 1 — Archive Handling: 7z list/extract on real Kansa ZIP archives.
Layer 2 — File Analysis: file, sha256sum, grep, stat on extracted CSVs.
Layer 3 — Disk Image Analysis: fls, icat, mmls, file on EWF/NTFS E01.
Layer 4 — Server Envelope: run_command → build_response → validate fields.
Layer 5 — Catalog Gap Detection: installed-but-uncataloged tools flagged.
Layer 6 — Negative Paths: uncataloged binary, blocked path, bad evidence.

Evidence at /cases/integration-test/evidence/. All tests skip cleanly when
evidence is absent.
"""

from __future__ import annotations

import re
import shutil

import pytest

pytestmark = pytest.mark.integration

EVIDENCE_BASE = "/cases/integration-test"


# ===================================================================
# Layer 1: Archive Handling
# ===================================================================


class TestArchiveHandling:
    def test_7z_list_archive(self, evidence_dir, run_command_executor):
        """7z l on shimcache.zip lists CSV filenames."""
        result = run_command_executor(
            ["7z", "l", str(evidence_dir / "kansa-post-intrusion_shimcache.zip")],
            purpose="integration test: list shimcache archive",
        )
        assert result["exit_code"] == 0
        assert "AppCompatCache" in result["stdout"]
        assert ".csv" in result["stdout"].lower()

    def test_7z_extract_archive(self, extraction_dir):
        """Extraction fixture produced CSV files on disk."""
        csvs = list(extraction_dir.rglob("*.csv"))
        assert len(csvs) == 20, f"Expected 20 CSVs, got {len(csvs)}"

    def test_7z_list_large_archive(self, evidence_dir, run_command_executor):
        """7z l on kansa-post-intrusion.zip lists 381 files."""
        archive = evidence_dir / "kansa-post-intrusion.zip"
        if not archive.exists():
            pytest.skip("kansa-post-intrusion.zip not found")

        result = run_command_executor(
            ["7z", "l", str(archive)],
            purpose="integration test: list large Kansa archive",
        )
        assert result["exit_code"] == 0
        # The archive contains 381 files
        assert "381 files" in result["stdout"] or result["stdout"].count(".csv") > 100


# ===================================================================
# Layer 2: File Analysis on Extracted Content
# ===================================================================


class TestFileAnalysis:
    def test_file_identifies_csv(self, extracted_csvs, run_command_executor):
        """file command identifies extracted CSV as text/CSV."""
        result = run_command_executor(
            ["file", str(extracted_csvs[0])],
            purpose="integration test: identify CSV file type",
        )
        assert result["exit_code"] == 0
        stdout_lower = result["stdout"].lower()
        assert "text" in stdout_lower or "csv" in stdout_lower

    def test_sha256sum_format(self, extracted_csvs, run_command_executor):
        """sha256sum produces a 64-character hex hash."""
        result = run_command_executor(
            ["sha256sum", str(extracted_csvs[0])],
            purpose="integration test: SHA-256 hash of CSV",
        )
        assert result["exit_code"] == 0
        assert re.match(r"[a-f0-9]{64}", result["stdout"])

    def test_grep_csv_content(self, extracted_csvs, run_command_executor):
        """grep -c counts lines in shimcache CSV.

        Shimcache CSVs are UTF-16 encoded, so plain-text pattern matching
        requires -P with null-byte patterns. A line count (-c) is the
        common forensic workflow: "how many entries in this CSV?"
        """
        result = run_command_executor(
            ["grep", "-c", "", str(extracted_csvs[0])],
            purpose="integration test: count CSV lines",
        )
        assert result["exit_code"] == 0
        line_count = int(result["stdout"].strip())
        assert line_count > 10

    def test_stat_shows_metadata(self, extracted_csvs, run_command_executor):
        """stat shows file metadata including Size."""
        result = run_command_executor(
            ["stat", str(extracted_csvs[0])],
            purpose="integration test: stat on extracted CSV",
        )
        assert result["exit_code"] == 0
        assert "Size:" in result["stdout"] or "size" in result["stdout"].lower()


# ===================================================================
# Layer 3: Disk Image Analysis
# ===================================================================


class TestDiskImageAnalysis:
    """Tests against base-dc-cdrive.E01 (EWF/NTFS partition image).

    This is a partition image (C: volume only, no MBR/GPT), so:
    - fls -o 0 reads NTFS directly
    - mmls returns exit 1 (no partition table — expected)

    If a full-disk image is substituted, fls -o 0 will fail and mmls
    will succeed. Update assertions accordingly.
    """

    def test_fls_lists_ntfs_root(self, e01_image, run_command_executor):
        """fls -o 0 on E01 lists NTFS root entries ($MFT, Users, etc.)."""
        result = run_command_executor(
            ["fls", "-o", "0", str(e01_image)],
            purpose="integration test: list NTFS root",
        )
        assert result["exit_code"] == 0
        stdout = result["stdout"]
        assert "$MFT" in stdout
        assert "Users" in stdout

    def test_fls_recursive(self, e01_image, run_command_executor):
        """fls -r -o 0 on E01 produces recursive listing."""
        result = run_command_executor(
            ["fls", "-r", "-o", "0", str(e01_image)],
            purpose="integration test: recursive NTFS listing",
        )
        assert result["exit_code"] == 0
        # Recursive listing produces many lines
        lines = result["stdout"].splitlines()
        assert len(lines) > 100

    def test_icat_extracts_small_file(self, e01_image, run_command_executor):
        """Find a small file inode via fls, then extract with icat.

        Uses non-recursive fls on Users/ dir to find desktop.ini (small
        text file), avoiding stdout truncation from large recursive
        listings. The executor caps output at 50K bytes.
        """
        # List the Users directory (inode 465) to find desktop.ini
        fls_result = run_command_executor(
            ["fls", "-o", "0", str(e01_image), "465"],
            purpose="integration test: list Users dir for icat target",
        )
        assert fls_result["exit_code"] == 0

        # Parse fls output for desktop.ini inode
        # Format: r/r 22177-128-1:	desktop.ini
        inode = None
        for line in fls_result["stdout"].splitlines():
            if "desktop.ini" in line and "r/r" in line:
                match = re.search(r"(\d+)-\d+-\d+:", line)
                if match:
                    inode = match.group(1)
                    break

        if inode is None:
            pytest.skip("Could not find desktop.ini inode in fls output")

        icat_result = run_command_executor(
            ["icat", "-o", "0", str(e01_image), inode],
            purpose="integration test: extract file by inode",
        )
        assert icat_result["exit_code"] == 0
        assert len(icat_result["stdout"]) > 0

    def test_mmls_on_partitionless_image(self, e01_image, run_command_executor):
        """mmls on a partition image (no MBR/GPT) returns exit 1.

        This is expected: the E01 is a C: volume only, not a full disk.
        """
        result = run_command_executor(
            ["mmls", str(e01_image)],
            purpose="integration test: mmls on partitionless image",
        )
        assert result["exit_code"] == 1

    def test_file_identifies_e01(self, e01_image, run_command_executor):
        """file command identifies E01 as EWF/Expert Witness format."""
        result = run_command_executor(
            ["file", str(e01_image)],
            purpose="integration test: identify E01 file type",
        )
        assert result["exit_code"] == 0
        stdout_lower = result["stdout"].lower()
        assert "ewf" in stdout_lower or "expert witness" in stdout_lower


# ===================================================================
# Layer 4: Server Envelope Validation
# ===================================================================


class TestServerEnvelope:
    """Replicate server pipeline: run_command → build_response → validate.

    Uses real tool execution against E01 evidence, then wraps through
    the same build_response code path as server.py's run_command tool.
    """

    def _call_through_envelope(self, command, monkeypatch, tmp_path):
        """Replicate the server's run_command pipeline with real execution."""
        import time

        monkeypatch.setenv("AIIR_EXAMINER", "integration")
        monkeypatch.setenv("AIIR_CASE_DIR", str(tmp_path))
        (tmp_path / "audit").mkdir(exist_ok=True)

        from sift_mcp.audit import AuditWriter
        from sift_mcp.catalog import clear_catalog_cache, get_tool_def
        from sift_mcp.response import build_response
        from sift_mcp.tools.generic import run_command

        clear_catalog_cache()
        audit = AuditWriter(mcp_name="sift-mcp")
        evidence_id = audit._next_evidence_id()
        start = time.monotonic()

        exec_result = run_command(command, purpose="envelope test")
        elapsed = time.monotonic() - start

        binary = command[0].split("/")[-1]
        td = get_tool_def(binary)
        fk_name = td.knowledge_name if td else binary

        response = build_response(
            tool_name="run_command",
            success=exec_result["exit_code"] == 0,
            data=exec_result,
            evidence_id=evidence_id,
            output_format="text",
            elapsed_seconds=elapsed,
            exit_code=exec_result["exit_code"],
            command=command,
            fk_tool_name=fk_name,
        )

        audit.log(
            tool="run_command",
            params={"command": command, "purpose": "envelope test"},
            result_summary={"exit_code": exec_result["exit_code"]},
            evidence_id=evidence_id,
            elapsed_ms=elapsed * 1000,
        )

        clear_catalog_cache()
        return response

    def test_envelope_structure(self, e01_image, monkeypatch, tmp_path):
        """Successful fls produces envelope with all required fields."""
        response = self._call_through_envelope(
            ["fls", "-o", "0", str(e01_image)],
            monkeypatch, tmp_path,
        )
        assert response["success"] is True
        assert response["tool"] == "run_command"
        assert response["data"] is not None
        assert response["evidence_id"]
        assert response["examiner"] == "integration"
        assert response["output_format"] == "text"
        assert response["discipline_reminder"]
        assert isinstance(response["metadata"], dict)

    def test_evidence_id_format(self, e01_image, monkeypatch, tmp_path):
        """Evidence ID matches sift-{examiner}-{YYYYMMDD}-{NNN}."""
        response = self._call_through_envelope(
            ["fls", "-o", "0", str(e01_image)],
            monkeypatch, tmp_path,
        )
        eid = response["evidence_id"]
        assert re.match(r"sift-integration-\d{8}-\d{3}$", eid), (
            f"Bad evidence_id format: {eid}"
        )

    def test_evidence_id_sequencing(self, monkeypatch, tmp_path):
        """Evidence IDs increment across calls."""
        monkeypatch.setenv("AIIR_EXAMINER", "integration")
        monkeypatch.setenv("AIIR_CASE_DIR", str(tmp_path))
        (tmp_path / "audit").mkdir(exist_ok=True)

        from sift_mcp.audit import AuditWriter

        audit = AuditWriter(mcp_name="sift-mcp")
        eid1 = audit._next_evidence_id()
        eid2 = audit._next_evidence_id()

        seq1 = int(eid1.rsplit("-", 1)[1])
        seq2 = int(eid2.rsplit("-", 1)[1])
        assert seq2 == seq1 + 1

    def test_fk_enrichment_present(self, e01_image, monkeypatch, tmp_path):
        """fls has FK data; discipline_reminder is a non-empty string."""
        response = self._call_through_envelope(
            ["fls", "-o", "0", str(e01_image)],
            monkeypatch, tmp_path,
        )
        assert "discipline_reminder" in response
        assert isinstance(response["discipline_reminder"], str)
        assert len(response["discipline_reminder"]) > 10

    def test_metadata_fields(self, e01_image, monkeypatch, tmp_path):
        """Metadata contains elapsed_seconds (float >= 0), exit_code, command."""
        response = self._call_through_envelope(
            ["fls", "-o", "0", str(e01_image)],
            monkeypatch, tmp_path,
        )
        meta = response["metadata"]
        assert "elapsed_seconds" in meta
        assert isinstance(meta["elapsed_seconds"], float)
        assert meta["elapsed_seconds"] >= 0
        assert meta["exit_code"] == 0
        assert meta["command"][0].endswith("fls")

    def test_failed_tool_envelope(self, e01_image, monkeypatch, tmp_path):
        """Nonexistent file → success=False, valid envelope."""
        response = self._call_through_envelope(
            ["fls", str(e01_image.parent / "nonexistent.dd")],
            monkeypatch, tmp_path,
        )
        assert response["success"] is False
        assert response["evidence_id"]
        assert response["metadata"]["exit_code"] != 0


# ===================================================================
# Layer 5: Catalog Gap Detection
# ===================================================================


class TestCatalogGaps:
    """Tests that installed-but-uncataloged tools are flagged.

    Each test uses pytest.xfail with a clear message identifying the
    gap. Adding these to catalog YAML is a separate task.
    """

    def _check_gap(self, tool_name: str):
        """Assert tool is installed but NOT in catalog, then xfail."""
        from sift_mcp.catalog import is_in_catalog

        path = shutil.which(tool_name)
        if path is None:
            pytest.skip(f"{tool_name} not installed")

        if is_in_catalog(tool_name):
            return  # No gap — tool is now cataloged, test passes

        pytest.xfail(
            f"CATALOG GAP: {tool_name} installed at {path} "
            f"but not in sift-mcp catalog"
        )

    def test_img_stat_catalog_gap(self):
        self._check_gap("img_stat")

    def test_ewfinfo_catalog_gap(self):
        self._check_gap("ewfinfo")

    def test_istat_catalog_gap(self):
        self._check_gap("istat")

    def test_foremost_catalog_gap(self):
        self._check_gap("foremost")

    # Full parametrized scan over all 35 known uncataloged tools.
    # Skips any that are not installed on this system.
    @pytest.mark.parametrize("tool_name", [
        # SleuthKit (27)
        "img_stat", "img_cat", "sorter", "sigfind", "ifind", "ffind",
        "tsk_recover", "tsk_loaddb", "tsk_comparedir", "tsk_gettimes",
        "istat", "fsstat", "ils", "blkcalc", "blkcat", "blkstat",
        "pstat", "mmcat", "mmstat", "jcat", "jls", "fcat", "hfind",
        "jpeg_extract", "srch_strings", "usnjls", "fiwalk",
        # EWF (3)
        "ewfinfo", "ewfverify", "ewfexport",
        # Carving (2)
        "foremost", "scalpel",
        # Plaso (3)
        "pinfo.py", "image_export.py", "psteal.py",
        # Image (1)
        "xmount",
    ])
    def test_parametrized_gap_scan(self, tool_name):
        self._check_gap(tool_name)


# ===================================================================
# Layer 6: Negative Paths
# ===================================================================


class TestNegativePaths:
    def test_uncataloged_binary_rejected(self):
        """Unknown binaries are rejected by the catalog gate."""
        from sift_mcp.exceptions import ToolNotInCatalogError
        from sift_mcp.tools.generic import run_command

        with pytest.raises(ToolNotInCatalogError, match="not in the approved"):
            run_command(
                ["totally_fake_binary", "--version"],
                purpose="should be rejected",
            )

    def test_blocked_path_rejected(self):
        """Paths under blocked directories are rejected."""
        from sift_mcp.tools.generic import run_command

        with pytest.raises(ValueError, match="blocked system directory"):
            run_command(
                ["fls", "/tmp/something"],
                purpose="should be rejected",
            )

    def test_nonexistent_evidence_error(self, e01_image, monkeypatch, tmp_path):
        """Running a tool on a nonexistent file returns success=False envelope."""
        import time

        monkeypatch.setenv("AIIR_EXAMINER", "integration")
        monkeypatch.setenv("AIIR_CASE_DIR", str(tmp_path))
        (tmp_path / "audit").mkdir(exist_ok=True)

        from sift_mcp.audit import AuditWriter
        from sift_mcp.response import build_response
        from sift_mcp.tools.generic import run_command

        evidence_id = AuditWriter(mcp_name="sift-mcp")._next_evidence_id()
        start = time.monotonic()
        exec_result = run_command(
            ["fls", str(e01_image.parent / "does_not_exist.dd")],
            purpose="negative test: nonexistent file",
        )
        elapsed = time.monotonic() - start

        response = build_response(
            tool_name="run_command",
            success=exec_result["exit_code"] == 0,
            data=exec_result,
            evidence_id=evidence_id,
            elapsed_seconds=elapsed,
            exit_code=exec_result["exit_code"],
            command=["fls", "nonexistent"],
        )

        assert response["success"] is False
        assert response["metadata"]["exit_code"] != 0
