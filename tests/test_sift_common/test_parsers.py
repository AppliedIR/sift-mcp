"""Unit tests for sift_common.parsers — CSV, JSON, JSONL, text parsing."""

import json

from sift_common.parsers.csv_parser import parse_csv, parse_csv_file
from sift_common.parsers.json_parser import parse_json, parse_jsonl
from sift_common.parsers.text_parser import extract_lines, parse_text

# ---------------------------------------------------------------------------
# CSV parser
# ---------------------------------------------------------------------------


class TestParseCsv:
    def test_basic_csv(self):
        text = "name,age\nAlice,30\nBob,25\n"
        result = parse_csv(text)
        assert result["total_rows"] == 2
        assert len(result["rows"]) == 2
        assert result["rows"][0]["name"] == "Alice"
        assert result["columns"] == ["name", "age"]
        assert result["truncated"] is False

    def test_empty_input(self):
        result = parse_csv("")
        assert result["rows"] == []
        assert result["total_rows"] == 0

    def test_whitespace_only(self):
        result = parse_csv("   \n  \n")
        assert result["rows"] == []

    def test_header_only(self):
        result = parse_csv("name,age\n")
        assert result["total_rows"] == 0
        assert result["columns"] == ["name", "age"]

    def test_max_rows_truncation(self):
        header = "val\n"
        rows = "\n".join(str(i) for i in range(100))
        result = parse_csv(header + rows, max_rows=10)
        assert len(result["rows"]) == 10
        assert result["total_rows"] == 99
        assert result["truncated"] is True

    def test_byte_budget(self):
        header = "data\n"
        rows = "\n".join("x" * 50 for _ in range(100))
        result = parse_csv(header + rows, byte_budget=200)
        assert len(result["rows"]) < 100
        assert result["truncated"] is True

    def test_preview_bytes_tracked(self):
        text = "name\nAlice\nBob\n"
        result = parse_csv(text, byte_budget=1000)
        assert result["preview_bytes"] > 0

    def test_no_budget_no_tracking(self):
        text = "name\nAlice\n"
        result = parse_csv(text)
        assert result["preview_bytes"] == 0


class TestParseCsvFile:
    def test_reads_file(self, tmp_path):
        csv_file = tmp_path / "data.csv"
        csv_file.write_text("name,value\nfoo,1\nbar,2\n")
        result = parse_csv_file(str(csv_file))
        assert len(result["rows"]) == 2

    def test_file_not_found(self, tmp_path):
        result = parse_csv_file(str(tmp_path / "nonexistent.csv"))
        assert result["rows"] == []
        assert "parse_error" in result

    def test_file_too_large(self, tmp_path):
        csv_file = tmp_path / "huge.csv"
        # Create a file > 50MB via truncate (sparse)
        csv_file.write_text("x")
        import os

        os.truncate(str(csv_file), 60_000_000)
        result = parse_csv_file(str(csv_file))
        assert "error" in result
        assert "too large" in result["error"]

    def test_max_rows_default(self, tmp_path):
        csv_file = tmp_path / "data.csv"
        header = "val\n"
        rows = "\n".join(str(i) for i in range(2000))
        csv_file.write_text(header + rows)
        result = parse_csv_file(str(csv_file))
        assert len(result["rows"]) == 1000  # default max_rows


# ---------------------------------------------------------------------------
# JSON parser
# ---------------------------------------------------------------------------


class TestParseJson:
    def test_single_object(self):
        result = parse_json('{"key": "value"}')
        assert result["data"] == {"key": "value"}
        assert result["total_entries"] == 1
        assert result["truncated"] is False

    def test_array(self):
        result = parse_json("[1, 2, 3]")
        assert result["data"] == [1, 2, 3]
        assert result["total_entries"] == 3

    def test_empty_input(self):
        result = parse_json("")
        assert result["data"] is None
        assert result["total_entries"] == 0

    def test_invalid_json(self):
        result = parse_json("not json {{{")
        assert result["data"] is None
        assert "parse_error" in result

    def test_max_entries_truncation(self):
        data = json.dumps(list(range(100)))
        result = parse_json(data, max_entries=10)
        assert len(result["data"]) == 10
        assert result["total_entries"] == 100
        assert result["truncated"] is True

    def test_byte_budget(self):
        data = json.dumps([{"x": "a" * 50} for _ in range(100)])
        result = parse_json(data, byte_budget=200)
        assert len(result["data"]) < 100
        assert result["truncated"] is True

    def test_nested_object(self):
        result = parse_json('{"a": {"b": [1, 2]}}')
        assert result["data"]["a"]["b"] == [1, 2]


class TestParseJsonl:
    def test_basic_jsonl(self):
        text = '{"a": 1}\n{"a": 2}\n{"a": 3}\n'
        result = parse_jsonl(text)
        assert result["total_entries"] == 3
        assert len(result["data"]) == 3
        assert result["data"][0] == {"a": 1}

    def test_empty_input(self):
        result = parse_jsonl("")
        assert result["data"] == []
        assert result["total_entries"] == 0

    def test_blank_lines_skipped(self):
        text = '{"a": 1}\n\n{"a": 2}\n\n'
        result = parse_jsonl(text)
        assert result["total_entries"] == 2

    def test_invalid_line_preserved_as_raw(self):
        text = '{"a": 1}\nnot json\n{"a": 3}\n'
        result = parse_jsonl(text)
        assert result["total_entries"] == 3
        assert result["data"][1] == {"_raw": "not json"}

    def test_max_entries_truncation(self):
        lines = "\n".join(json.dumps({"i": i}) for i in range(100))
        result = parse_jsonl(lines, max_entries=10)
        assert len(result["data"]) == 10
        assert result["total_entries"] == 100
        assert result["truncated"] is True

    def test_byte_budget(self):
        lines = "\n".join(json.dumps({"data": "x" * 50}) for _ in range(100))
        result = parse_jsonl(lines, byte_budget=200)
        assert len(result["data"]) < 100
        assert result["truncated"] is True


# ---------------------------------------------------------------------------
# Text parser
# ---------------------------------------------------------------------------


class TestParseText:
    def test_basic_text(self):
        result = parse_text("line1\nline2\nline3\n")
        assert result["total_lines"] == 4  # trailing newline creates empty 4th
        assert result["preview_lines"] == 4
        assert result["truncated"] is False

    def test_empty_input(self):
        result = parse_text("")
        assert result["total_lines"] == 1  # split("") gives [""]
        assert result["lines"] == [""]

    def test_max_lines_truncation(self):
        text = "\n".join(f"line{i}" for i in range(100))
        result = parse_text(text, max_lines=10)
        assert len(result["lines"]) == 10
        assert result["total_lines"] == 100
        assert result["truncated"] is True

    def test_byte_budget(self):
        text = "\n".join("x" * 50 for _ in range(100))
        result = parse_text(text, byte_budget=200)
        assert len(result["lines"]) < 100
        assert result["truncated"] is True

    def test_preview_bytes_tracked(self):
        text = "hello\nworld\n"
        result = parse_text(text, byte_budget=1000)
        assert result["preview_bytes"] > 0


class TestExtractLines:
    def test_basic_extraction(self):
        text = "a\nb\nc\nd\ne"
        result = extract_lines(text, start=1, count=2)
        assert result == ["b", "c"]

    def test_from_start(self):
        text = "a\nb\nc"
        result = extract_lines(text, start=0, count=2)
        assert result == ["a", "b"]

    def test_past_end(self):
        text = "a\nb"
        result = extract_lines(text, start=0, count=10)
        assert result == ["a", "b"]

    def test_empty_input(self):
        result = extract_lines("", start=0, count=5)
        assert result == [""]
