"""Tests for output parsers."""

import json
import pytest


class TestCsvParser:
    def test_parse_csv(self):
        from sift_mcp.parsers.csv_parser import parse_csv
        text = "Name,Value,Count\nalpha,100,1\nbeta,200,2\n"
        result = parse_csv(text)
        assert result["total_rows"] == 2
        assert result["truncated"] is False
        assert result["columns"] == ["Name", "Value", "Count"]
        assert result["rows"][0]["Name"] == "alpha"

    def test_parse_csv_empty(self):
        from sift_mcp.parsers.csv_parser import parse_csv
        result = parse_csv("")
        assert result["total_rows"] == 0
        assert result["rows"] == []

    def test_parse_csv_truncation(self):
        from sift_mcp.parsers.csv_parser import parse_csv
        lines = ["Name,Value"] + [f"item{i},{i}" for i in range(100)]
        text = "\n".join(lines)
        result = parse_csv(text, max_rows=10)
        assert len(result["rows"]) == 10
        assert result["total_rows"] >= 90  # At least 90 rows total
        assert result["truncated"] is True

    def test_parse_csv_file(self, tmp_path):
        from sift_mcp.parsers.csv_parser import parse_csv_file
        csv_file = tmp_path / "test.csv"
        csv_file.write_text("A,B\n1,2\n3,4\n")
        result = parse_csv_file(str(csv_file))
        assert len(result["rows"]) == 2


class TestJsonParser:
    def test_parse_json_array(self):
        from sift_mcp.parsers.json_parser import parse_json
        result = parse_json('[{"a":1},{"a":2}]')
        assert result["total_entries"] == 2
        assert result["data"][0]["a"] == 1

    def test_parse_json_object(self):
        from sift_mcp.parsers.json_parser import parse_json
        result = parse_json('{"key":"value"}')
        assert result["total_entries"] == 1
        assert result["data"]["key"] == "value"

    def test_parse_json_empty(self):
        from sift_mcp.parsers.json_parser import parse_json
        result = parse_json("")
        assert result["data"] is None

    def test_parse_json_truncation(self):
        from sift_mcp.parsers.json_parser import parse_json
        data = json.dumps([{"i": i} for i in range(100)])
        result = parse_json(data, max_entries=10)
        assert len(result["data"]) == 10
        assert result["truncated"] is True

    def test_parse_jsonl(self):
        from sift_mcp.parsers.json_parser import parse_jsonl
        text = '{"a":1}\n{"a":2}\n{"a":3}\n'
        result = parse_jsonl(text)
        assert result["total_entries"] == 3
        assert len(result["data"]) == 3

    def test_parse_jsonl_truncation(self):
        from sift_mcp.parsers.json_parser import parse_jsonl
        lines = [json.dumps({"i": i}) for i in range(100)]
        result = parse_jsonl("\n".join(lines), max_entries=5)
        assert len(result["data"]) == 5
        assert result["truncated"] is True


class TestTextParser:
    def test_parse_text(self):
        from sift_mcp.parsers.text_parser import parse_text
        text = "\n".join(f"line {i}" for i in range(10))
        result = parse_text(text)
        assert result["total_lines"] == 10
        assert result["truncated"] is False

    def test_parse_text_truncation(self):
        from sift_mcp.parsers.text_parser import parse_text
        text = "\n".join(f"line {i}" for i in range(1000))
        result = parse_text(text, max_lines=50)
        assert len(result["lines"]) == 50
        assert result["truncated"] is True

    def test_extract_lines(self):
        from sift_mcp.parsers.text_parser import extract_lines
        text = "\n".join(f"line {i}" for i in range(100))
        lines = extract_lines(text, start=10, count=5)
        assert len(lines) == 5
        assert lines[0] == "line 10"
