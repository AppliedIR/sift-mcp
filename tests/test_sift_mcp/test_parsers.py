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

    def test_byte_budget_caps_rows(self):
        from sift_mcp.parsers.csv_parser import parse_csv
        lines = ["Name,Value,Extra"] + [f"item{i},{i}," + "x" * 80 for i in range(1000)]
        text = "\n".join(lines)
        result = parse_csv(text, byte_budget=1024)
        assert result["preview_rows"] < 1000
        assert result["preview_bytes"] <= 1024
        assert result["truncated"] is True
        assert result["total_rows"] >= 990  # ~1000 data rows

    def test_byte_budget_zero_means_unlimited(self):
        from sift_mcp.parsers.csv_parser import parse_csv
        lines = ["Name,Value"] + [f"item{i},{i}" for i in range(50)]
        text = "\n".join(lines)
        result = parse_csv(text, byte_budget=0)
        assert result["preview_rows"] == 50
        assert result["truncated"] is False

    def test_byte_budget_returns_complete_rows(self):
        from sift_mcp.parsers.csv_parser import parse_csv
        lines = ["Name,Value"] + [f"item{i},{i}" for i in range(100)]
        text = "\n".join(lines)
        result = parse_csv(text, byte_budget=500)
        # Each row should be complete (all columns present)
        for row in result["rows"]:
            assert "Name" in row
            assert "Value" in row

    def test_wide_csv_fewer_rows(self):
        from sift_mcp.parsers.csv_parser import parse_csv
        # 50-column CSV should return fewer rows than 3-column for same budget
        cols_3 = ["A,B,C"] + [f"x,y,z" for _ in range(100)]
        cols_50 = [",".join(f"C{i}" for i in range(50))] + [
            ",".join(f"val{i}" for i in range(50)) for _ in range(100)
        ]
        result_3 = parse_csv("\n".join(cols_3), byte_budget=1024)
        result_50 = parse_csv("\n".join(cols_50), byte_budget=1024)
        assert result_50["preview_rows"] < result_3["preview_rows"]

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

    def test_byte_budget_caps_entries(self):
        from sift_mcp.parsers.json_parser import parse_json
        data = json.dumps([{"id": i, "data": "x" * 100} for i in range(500)])
        result = parse_json(data, byte_budget=1024)
        assert result["preview_entries"] < 500
        assert result["preview_bytes"] <= 1024
        assert result["truncated"] is True
        assert result["total_entries"] == 500

    def test_json_byte_budget_zero_means_unlimited(self):
        from sift_mcp.parsers.json_parser import parse_json
        data = json.dumps([{"i": i} for i in range(50)])
        result = parse_json(data, byte_budget=0)
        assert result["preview_entries"] == 50
        assert result["truncated"] is False

    def test_jsonl_byte_budget(self):
        from sift_mcp.parsers.json_parser import parse_jsonl
        lines = [json.dumps({"id": i, "payload": "y" * 100}) for i in range(200)]
        result = parse_jsonl("\n".join(lines), byte_budget=1024)
        assert result["preview_entries"] < 200
        assert result["preview_bytes"] <= 1024
        assert result["truncated"] is True
        assert result["total_entries"] == 200


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

    def test_byte_budget_caps_lines(self):
        from sift_mcp.parsers.text_parser import parse_text
        text = "\n".join(f"line {i:04d} " + "x" * 100 for i in range(500))
        result = parse_text(text, byte_budget=1024)
        assert result["preview_lines"] < 500
        assert result["preview_bytes"] <= 1024
        assert result["truncated"] is True
        assert result["total_lines"] == 500

    def test_byte_budget_zero_means_unlimited(self):
        from sift_mcp.parsers.text_parser import parse_text
        text = "\n".join(f"line {i}" for i in range(100))
        result = parse_text(text, byte_budget=0)
        assert result["preview_lines"] == 100
        assert result["truncated"] is False

    def test_preview_bytes_accurate(self):
        from sift_mcp.parsers.text_parser import parse_text
        text = "\n".join(f"line {i}" for i in range(10))
        result = parse_text(text, byte_budget=10240)
        # All lines fit within budget
        total_bytes = sum(len(line.encode("utf-8")) + 1 for line in text.split("\n"))
        assert result["preview_bytes"] == total_bytes

    def test_long_lines_fewer_in_preview(self):
        from sift_mcp.parsers.text_parser import parse_text
        text = "\n".join("x" * 1024 for _ in range(100))
        result = parse_text(text, byte_budget=10240)
        assert result["preview_lines"] <= 10  # ~1KB per line, 10KB budget
        assert result["truncated"] is True

    def test_extract_lines(self):
        from sift_mcp.parsers.text_parser import extract_lines
        text = "\n".join(f"line {i}" for i in range(100))
        lines = extract_lines(text, start=10, count=5)
        assert len(lines) == 5
        assert lines[0] == "line 10"
