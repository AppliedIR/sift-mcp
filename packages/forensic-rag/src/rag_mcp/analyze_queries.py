#!/usr/bin/env python3
"""
Query Analysis - Analyze logs, recommend tuning, and apply with approval.

Usage:
    python -m rag_mcp.analyze_queries                    # Full interactive workflow
    python -m rag_mcp.analyze_queries --report-only      # Just show report, no changes
    python -m rag_mcp.analyze_queries --since 7d         # Analyze last 7 days
    python -m rag_mcp.analyze_queries --approver "agent" # Set approver name

Interactive Workflow:
1. Analyzes query metrics and attention logs
2. Generates specific recommendations with rationale
3. Presents recommendations and asks for approval (Y/N for each)
4. Applies approved changes to tuning_config.json
5. Logs all changes for audit trail

Designed to work with both human operators and AI agents.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional

from .tuning_config import load_tuning_config, save_tuning_config, TuningConfig

# Log locations
PROJECT_ROOT = Path(__file__).parent.parent.parent
DEFAULT_LOGS_DIR = PROJECT_ROOT / "logs"
DEFAULT_METRICS_LOG = DEFAULT_LOGS_DIR / "query_metrics.log"
DEFAULT_ATTENTION_LOG = DEFAULT_LOGS_DIR / "attention.log"

# Safe bounds for automated adjustments
MIN_THRESHOLD = 0.40  # Never go below this
MAX_THRESHOLD = 0.70  # Never go above this
MIN_BOOST = 1.0       # No boost
MAX_BOOST = 1.30      # Maximum 30% boost


@dataclass
class QueryStats:
    """Statistics for a category of queries."""
    count: int = 0
    total_score: float = 0.0
    min_score: float = 1.0
    max_score: float = 0.0
    scores: list[float] = field(default_factory=list)
    zero_results: int = 0
    low_score_count: int = 0
    augmented_count: int = 0

    @property
    def avg_score(self) -> float:
        return self.total_score / self.count if self.count > 0 else 0.0

    @property
    def p10_score(self) -> float:
        """10th percentile score (used for threshold recommendations)."""
        if not self.scores:
            return 0.0
        sorted_scores = sorted(self.scores)
        idx = max(0, int(len(sorted_scores) * 0.10) - 1)
        return sorted_scores[idx]

    @property
    def p25_score(self) -> float:
        """25th percentile score."""
        if not self.scores:
            return 0.0
        sorted_scores = sorted(self.scores)
        idx = max(0, int(len(sorted_scores) * 0.25) - 1)
        return sorted_scores[idx]

    def add(self, score: float, result_count: int, augmented: bool) -> None:
        self.count += 1
        self.total_score += score
        self.scores.append(score)
        self.min_score = min(self.min_score, score)
        self.max_score = max(self.max_score, score)
        if result_count == 0:
            self.zero_results += 1
        if score < 0.5:
            self.low_score_count += 1
        if augmented:
            self.augmented_count += 1


@dataclass
class Recommendation:
    """A specific recommendation for tuning adjustment."""
    rec_type: str  # "threshold", "source_boost", "keyword_boost", "content_gap"
    description: str
    rationale: str
    current_value: Optional[float] = None
    recommended_value: Optional[float] = None
    query_type: Optional[str] = None  # For threshold recommendations
    source: Optional[str] = None  # For source_boost recommendations
    affected_queries: int = 0
    confidence: str = "medium"  # "high", "medium", "low"

    def to_config_format(self) -> dict[str, Any]:
        """Convert to format expected by TuningConfig.apply_recommendation()."""
        if self.rec_type == "threshold":
            return {
                "type": "threshold",
                "query_type": self.query_type,
                "new_value": self.recommended_value,
                "reason": self.rationale,
            }
        elif self.rec_type == "source_boost":
            return {
                "type": "source_boost",
                "source": self.source,
                "new_value": self.recommended_value,
                "reason": self.rationale,
            }
        elif self.rec_type == "keyword_boost":
            return {
                "type": "keyword_boost",
                "new_value": self.recommended_value,
                "reason": self.rationale,
            }
        return {}


@dataclass
class AnalysisResult:
    """Complete analysis result with recommendations."""
    period_start: Optional[datetime] = None
    period_end: Optional[datetime] = None
    total_queries: int = 0
    stats_by_type: dict[str, QueryStats] = field(default_factory=dict)
    mitre_id_stats: dict[str, QueryStats] = field(default_factory=dict)
    attention_issues: dict[str, list[dict]] = field(default_factory=lambda: defaultdict(list))
    content_gaps: list[str] = field(default_factory=list)
    recommendations: list[Recommendation] = field(default_factory=list)


def parse_log_line(line: str) -> Optional[dict[str, Any]]:
    """Parse a structured log line into a dictionary."""
    try:
        # Find the structured data part (after the log prefix)
        # Format: timestamp - logger - level - key=value pairs
        parts = line.split(" - ")
        if len(parts) < 4:
            return None

        data_str = parts[-1].strip()
        result = {}

        # Handle query= specially since it may contain spaces or mixed quotes
        query_match = re.search(r"query=(['\"])(.+?)\1$", data_str) or \
                      re.search(r"query=(.+)$", data_str)
        if query_match:
            result["query"] = query_match.group(2)
            data_str = data_str[:query_match.start()].strip()

        # Parse remaining key=value pairs
        for pair in re.findall(r"(\w+)=([^\s\[]+|\[[^\]]*\])", data_str):
            key, value = pair
            if value.lower() == "true":
                result[key] = True
            elif value.lower() == "false":
                result[key] = False
            elif re.match(r"^-?\d+\.?\d*$", value):
                result[key] = float(value) if "." in value else int(value)
            else:
                result[key] = value

        # Parse timestamp
        timestamp_str = parts[0].strip()
        try:
            result["timestamp"] = datetime.fromisoformat(timestamp_str.replace(",", "."))
        except ValueError:
            pass

        return result if result else None
    except Exception:
        return None


def analyze_logs(
    metrics_log: Optional[Path] = None,
    attention_log: Optional[Path] = None,
    since: Optional[timedelta] = None,
    current_config: Optional[TuningConfig] = None
) -> AnalysisResult:
    """
    Analyze query logs and generate recommendations.

    Args:
        metrics_log: Path to query metrics log file
        attention_log: Path to attention log file
        since: Only analyze logs from this time period
        current_config: Current tuning configuration

    Returns:
        AnalysisResult with statistics and recommendations
    """
    result = AnalysisResult()
    cutoff_time = datetime.now() - since if since else None
    config = current_config or TuningConfig()

    # Find log files
    if not metrics_log:
        metrics_log = DEFAULT_METRICS_LOG
    if not attention_log:
        attention_log = DEFAULT_ATTENTION_LOG

    # Analyze metrics log
    if metrics_log.exists():
        with open(metrics_log, encoding="utf-8") as f:
            for line in f:
                parsed = parse_log_line(line)
                if not parsed:
                    continue

                # Check time filter
                if cutoff_time and "timestamp" in parsed:
                    if parsed["timestamp"] < cutoff_time:
                        continue

                # Update period tracking
                if "timestamp" in parsed:
                    if not result.period_start or parsed["timestamp"] < result.period_start:
                        result.period_start = parsed["timestamp"]
                    if not result.period_end or parsed["timestamp"] > result.period_end:
                        result.period_end = parsed["timestamp"]

                result.total_queries += 1

                query_type = parsed.get("query_type", "unknown")
                top_score = parsed.get("top_score", 0.0)
                result_count = parsed.get("result_count", 0)
                augmented = parsed.get("augmented", False)

                # Stats by query type
                if query_type not in result.stats_by_type:
                    result.stats_by_type[query_type] = QueryStats()
                result.stats_by_type[query_type].add(top_score, result_count, augmented)

                # Track individual MITRE IDs
                if query_type == "mitre_id":
                    query = parsed.get("query", "")
                    mitre_ids = re.findall(r'T\d{4}(?:\.\d{3})?', query.upper())
                    for mid in mitre_ids:
                        if mid not in result.mitre_id_stats:
                            result.mitre_id_stats[mid] = QueryStats()
                        result.mitre_id_stats[mid].add(top_score, result_count, augmented)

    # Analyze attention log
    if attention_log.exists():
        with open(attention_log, encoding="utf-8") as f:
            for line in f:
                parsed = parse_log_line(line)
                if not parsed:
                    continue

                if cutoff_time and "timestamp" in parsed:
                    if parsed["timestamp"] < cutoff_time:
                        continue

                reasons = parsed.get("reasons", "")
                if isinstance(reasons, str):
                    reasons = reasons.strip("[]").split(",")

                for reason in reasons:
                    reason = reason.strip()
                    if reason:
                        result.attention_issues[reason].append({
                            "query": parsed.get("query", ""),
                            "score": parsed.get("top_score", 0.0),
                            "source": parsed.get("top_result_source", ""),
                        })

                if "zero_results" in reasons:
                    query = parsed.get("query", "")
                    if query and query not in result.content_gaps:
                        result.content_gaps.append(query)

    # Generate recommendations
    _generate_recommendations(result, config)

    return result


def _generate_recommendations(result: AnalysisResult, config: TuningConfig) -> None:
    """Generate tuning recommendations based on analysis."""

    # Threshold recommendations based on query type statistics
    for query_type, stats in result.stats_by_type.items():
        if stats.count < 20:  # Need sufficient data
            continue

        current_threshold = config.thresholds.get(query_type, 0.50)

        # If many queries are failing threshold, consider lowering
        low_pct = (stats.low_score_count / stats.count) if stats.count > 0 else 0
        if low_pct > 0.20:  # More than 20% below threshold
            # Recommend p25 score as new threshold (within bounds)
            new_threshold = max(MIN_THRESHOLD, min(MAX_THRESHOLD, stats.p25_score - 0.05))
            if new_threshold < current_threshold - 0.03:  # Significant change
                result.recommendations.append(Recommendation(
                    rec_type="threshold",
                    description=f"Lower {query_type} threshold from {current_threshold:.2f} to {new_threshold:.2f}",
                    rationale=f"{low_pct*100:.0f}% of {stats.count} queries scored below current threshold. "
                              f"P25 score is {stats.p25_score:.3f}.",
                    current_value=current_threshold,
                    recommended_value=round(new_threshold, 2),
                    query_type=query_type,
                    affected_queries=stats.low_score_count,
                    confidence="medium" if stats.count >= 50 else "low",
                ))

        # If threshold is very low and most queries score high, consider raising
        elif stats.p25_score > current_threshold + 0.15 and stats.avg_score > 0.70:
            new_threshold = min(MAX_THRESHOLD, stats.p25_score - 0.10)
            if new_threshold > current_threshold + 0.03:
                result.recommendations.append(Recommendation(
                    rec_type="threshold",
                    description=f"Raise {query_type} threshold from {current_threshold:.2f} to {new_threshold:.2f}",
                    rationale=f"Query scores are consistently high (avg {stats.avg_score:.3f}, P25 {stats.p25_score:.3f}). "
                              f"Raising threshold improves precision.",
                    current_value=current_threshold,
                    recommended_value=round(new_threshold, 2),
                    query_type=query_type,
                    affected_queries=stats.count,
                    confidence="medium",
                ))

    # Content gap recommendations
    if len(result.content_gaps) >= 5:
        # Group by pattern (e.g., MITRE IDs)
        mitre_gaps = [q for q in result.content_gaps if re.match(r'^T\d{4}', q.upper())]
        if mitre_gaps:
            result.recommendations.append(Recommendation(
                rec_type="content_gap",
                description=f"Add content for {len(mitre_gaps)} MITRE techniques with zero results",
                rationale=f"Queries for these MITRE IDs returned no results: {', '.join(mitre_gaps[:5])}{'...' if len(mitre_gaps) > 5 else ''}",
                affected_queries=len(mitre_gaps),
                confidence="high",
            ))


def format_report(result: AnalysisResult, config: TuningConfig) -> str:
    """Format analysis result as a report."""
    lines = []
    lines.append("=" * 70)
    lines.append("RAG QUERY ANALYSIS REPORT")
    lines.append("=" * 70)

    if result.period_start and result.period_end:
        lines.append(f"Period: {result.period_start.strftime('%Y-%m-%d %H:%M')} to {result.period_end.strftime('%Y-%m-%d %H:%M')}")
    lines.append(f"Total queries analyzed: {result.total_queries}")

    if result.total_queries == 0:
        lines.append("")
        lines.append("No query logs found. Run some queries first, then re-run analysis.")
        lines.append(f"Expected log location: {DEFAULT_METRICS_LOG}")
        return "\n".join(lines)

    lines.append("")

    # Stats by query type
    if result.stats_by_type:
        lines.append("-" * 70)
        lines.append("QUERY TYPE STATISTICS")
        lines.append("-" * 70)
        lines.append(f"{'Type':<15} {'Count':>8} {'Avg':>8} {'P25':>8} {'Min':>8} {'Low%':>8}")
        lines.append("-" * 70)
        for qtype, stats in sorted(result.stats_by_type.items()):
            low_pct = (stats.low_score_count / stats.count * 100) if stats.count > 0 else 0
            lines.append(
                f"{qtype:<15} {stats.count:>8} {stats.avg_score:>8.3f} "
                f"{stats.p25_score:>8.3f} {stats.min_score:>8.3f} {low_pct:>7.1f}%"
            )
        lines.append("")

    # Current configuration
    lines.append("-" * 70)
    lines.append("CURRENT TUNING CONFIGURATION")
    lines.append("-" * 70)
    lines.append("Thresholds:")
    for qtype, threshold in sorted(config.thresholds.items()):
        lines.append(f"  {qtype}: {threshold}")
    lines.append(f"Keyword boost: {config.keyword_boost}")
    lines.append(f"Source boosts: {config.source_boosts}")
    if config.last_modified:
        lines.append(f"Last modified: {config.last_modified} by {config.last_modified_by}")
    lines.append("")

    # Attention issues
    if result.attention_issues:
        lines.append("-" * 70)
        lines.append("ATTENTION ISSUES")
        lines.append("-" * 70)
        for reason, issues in sorted(result.attention_issues.items()):
            lines.append(f"  {reason}: {len(issues)} occurrences")
        lines.append("")

    # Content gaps
    if result.content_gaps:
        lines.append("-" * 70)
        lines.append(f"CONTENT GAPS ({len(result.content_gaps)} zero-result queries)")
        lines.append("-" * 70)
        for gap in result.content_gaps[:10]:
            lines.append(f"  - {gap}")
        if len(result.content_gaps) > 10:
            lines.append(f"  ... and {len(result.content_gaps) - 10} more")
        lines.append("")

    lines.append("=" * 70)
    return "\n".join(lines)


def format_recommendations(recommendations: list[Recommendation]) -> str:
    """Format recommendations for display."""
    if not recommendations:
        return "No recommendations at this time."

    lines = []
    lines.append("")
    lines.append("=" * 70)
    lines.append("RECOMMENDATIONS")
    lines.append("=" * 70)

    for i, rec in enumerate(recommendations, 1):
        lines.append("")
        lines.append(f"[{i}] {rec.description}")
        lines.append(f"    Type: {rec.rec_type}")
        lines.append(f"    Confidence: {rec.confidence}")
        lines.append(f"    Affected queries: {rec.affected_queries}")
        lines.append(f"    Rationale: {rec.rationale}")
        if rec.current_value is not None:
            lines.append(f"    Current value: {rec.current_value}")
        if rec.recommended_value is not None:
            lines.append(f"    Recommended value: {rec.recommended_value}")

    lines.append("")
    lines.append("=" * 70)
    return "\n".join(lines)


def interactive_approval(
    recommendations: list[Recommendation],
    config: TuningConfig,
    approver: str
) -> tuple[int, int]:
    """
    Interactively ask for approval of each recommendation.

    Args:
        recommendations: List of recommendations to approve
        config: TuningConfig to modify
        approver: Name of approver (human or agent)

    Returns:
        Tuple of (approved_count, skipped_count)
    """
    approved = 0
    skipped = 0

    actionable = [r for r in recommendations if r.rec_type != "content_gap"]

    if not actionable:
        print("\nNo actionable recommendations (content gaps require manual intervention).")
        return 0, len(recommendations)

    print("\n" + "=" * 70)
    print("APPROVAL REQUIRED")
    print("=" * 70)
    print(f"Approver: {approver}")
    print(f"Actionable recommendations: {len(actionable)}")
    print("")
    print("For each recommendation, enter:")
    print("  Y or yes  - Approve and apply")
    print("  N or no   - Skip this recommendation")
    print("  Q or quit - Stop and save approved changes")
    print("")

    for i, rec in enumerate(actionable, 1):
        print("-" * 70)
        print(f"[{i}/{len(actionable)}] {rec.description}")
        print(f"  Rationale: {rec.rationale}")
        if rec.current_value is not None and rec.recommended_value is not None:
            print(f"  Change: {rec.current_value} -> {rec.recommended_value}")
        print(f"  Confidence: {rec.confidence}")
        print("")

        while True:
            try:
                response = input("  Approve? [Y/N/Q]: ").strip().lower()
            except EOFError:
                # Non-interactive mode (e.g., piped input)
                response = "n"

            if response in ("y", "yes"):
                config.apply_recommendation(rec.to_config_format(), approved_by=approver)
                print("  -> APPROVED")
                approved += 1
                break
            elif response in ("n", "no"):
                print("  -> SKIPPED")
                skipped += 1
                break
            elif response in ("q", "quit"):
                print("  -> Stopping approval process")
                skipped += len(actionable) - i
                return approved, skipped
            else:
                print("  Please enter Y, N, or Q")

    return approved, skipped


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Analyze RAG query logs and recommend tuning adjustments",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m rag_mcp.analyze_queries
      Full interactive workflow - analyze, recommend, approve

  python -m rag_mcp.analyze_queries --report-only
      Just show report without making changes

  python -m rag_mcp.analyze_queries --since 7d --approver "claude-agent"
      Analyze last 7 days, set approver name for audit trail
"""
    )
    parser.add_argument(
        "--metrics-log", type=Path,
        help=f"Path to query metrics log (default: {DEFAULT_METRICS_LOG})"
    )
    parser.add_argument(
        "--attention-log", type=Path,
        help=f"Path to attention log (default: {DEFAULT_ATTENTION_LOG})"
    )
    parser.add_argument(
        "--since", type=str,
        help="Analyze logs since (e.g., 1d, 7d, 30d, 1h)"
    )
    parser.add_argument(
        "--report-only", action="store_true",
        help="Just show report, don't prompt for approval"
    )
    parser.add_argument(
        "--approver", type=str, default="interactive",
        help="Name of approver for audit trail (default: interactive)"
    )
    parser.add_argument(
        "--export", type=Path,
        help="Export analysis to JSON file"
    )
    args = parser.parse_args()

    # Parse time duration
    since = None
    if args.since:
        match = re.match(r"(\d+)([dhm])", args.since.lower())
        if match:
            value = int(match.group(1))
            unit = match.group(2)
            if unit == "d":
                since = timedelta(days=value)
            elif unit == "h":
                since = timedelta(hours=value)
            elif unit == "m":
                since = timedelta(minutes=value)
        else:
            print(f"WARNING: Invalid --since format '{args.since}'. Expected: <number><d|h|m> (e.g., 7d, 24h, 30m)", file=sys.stderr)

    # Load current config
    config = load_tuning_config()

    # Run analysis
    print("Analyzing query logs...")
    result = analyze_logs(
        metrics_log=args.metrics_log,
        attention_log=args.attention_log,
        since=since,
        current_config=config
    )

    # Show report
    print(format_report(result, config))

    # Show recommendations
    if result.recommendations:
        print(format_recommendations(result.recommendations))

    # Export if requested
    if args.export:
        export_data = {
            "period": {
                "start": result.period_start.isoformat() if result.period_start else None,
                "end": result.period_end.isoformat() if result.period_end else None,
            },
            "total_queries": result.total_queries,
            "stats_by_type": {
                k: {
                    "count": v.count,
                    "avg_score": v.avg_score,
                    "p25_score": v.p25_score,
                    "min_score": v.min_score,
                    "low_score_count": v.low_score_count,
                }
                for k, v in result.stats_by_type.items()
            },
            "content_gaps": result.content_gaps,
            "recommendations": [
                {
                    "type": r.rec_type,
                    "description": r.description,
                    "rationale": r.rationale,
                    "current_value": r.current_value,
                    "recommended_value": r.recommended_value,
                    "confidence": r.confidence,
                }
                for r in result.recommendations
            ],
        }
        import tempfile as _tempfile
        export_path = Path(args.export)
        export_path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = _tempfile.mkstemp(
            dir=export_path.parent,
            prefix=f".{export_path.name}.",
            suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(export_data, f, indent=2)
            os.replace(tmp_path, str(export_path))
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
        print(f"\nAnalysis exported to {args.export}")

    # Interactive approval
    if not args.report_only and result.recommendations:
        approved, skipped = interactive_approval(
            result.recommendations,
            config,
            args.approver
        )

        if approved > 0:
            save_tuning_config(config)
            print(f"\n{approved} change(s) applied and saved to tuning_config.json")
            print(f"{skipped} recommendation(s) skipped")
        else:
            print("\nNo changes applied.")

    elif not result.recommendations:
        print("\nNo recommendations - current tuning appears appropriate.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
