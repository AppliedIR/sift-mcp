"""Importer for process expectations.

Loads process parent-child relationship rules from YAML configuration file.

Sources:
- MemProcFS: https://github.com/ufrisk/MemProcFS (m_evil_proc2.c)
- SANS Hunt Evil: https://www.sans.org/posters/hunt-evil/
"""

import json
import logging
import sqlite3
from pathlib import Path
from typing import List, Dict, Optional

import yaml

logger = logging.getLogger(__name__)

# Default path to process expectations YAML
DEFAULT_YAML_PATH = Path(__file__).parent.parent.parent.parent / "data" / "process_expectations.yaml"


def load_process_expectations(yaml_path: Path = None) -> List[Dict]:
    """
    Load process expectations from YAML file.

    Args:
        yaml_path: Path to YAML file (default: data/process_expectations.yaml)

    Returns:
        List of process expectation dictionaries
    """
    if yaml_path is None:
        yaml_path = DEFAULT_YAML_PATH

    if not yaml_path.exists():
        logger.warning(f"Process expectations YAML not found: {yaml_path}")
        return []

    with open(yaml_path, 'r') as f:
        data = yaml.safe_load(f)

    return data.get('processes', [])


def import_process_expectations(db_path: Path, yaml_path: Path = None) -> dict:
    """
    Import process expectations into context.db.

    Args:
        db_path: Path to context.db
        yaml_path: Path to YAML file (optional)

    Returns:
        Dict with import statistics
    """
    stats = {
        'processes_imported': 0,
        'errors': 0
    }

    processes = load_process_expectations(yaml_path)
    if not processes:
        logger.warning("No process expectations to import")
        return stats

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        for proc in processes:
            try:
                # Handle valid_parents - can be list, null, or empty
                valid_parents = proc.get('valid_parents')
                parents_json = json.dumps(valid_parents) if valid_parents else None

                # Handle suspicious_parents - blacklist approach
                suspicious_parents = proc.get('suspicious_parents')
                suspicious_json = json.dumps(suspicious_parents) if suspicious_parents else None

                # Handle valid_paths
                valid_paths = proc.get('valid_paths')
                paths_json = json.dumps(valid_paths) if valid_paths else None

                # Handle valid_users
                valid_users = proc.get('valid_users')
                users_json = json.dumps(valid_users) if valid_users else None

                cursor.execute("""
                    INSERT OR REPLACE INTO expected_processes (
                        process_name_lower, valid_parents, suspicious_parents,
                        never_spawns_children, parent_exits, valid_paths,
                        user_type, valid_users, min_instances, max_instances,
                        per_session, required_args, source
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    proc['process_name'].lower(),
                    parents_json,
                    suspicious_json,
                    1 if proc.get('never_spawns_children') else 0,
                    1 if proc.get('parent_exits') else 0,
                    paths_json,
                    proc.get('user_type'),
                    users_json,
                    proc.get('min_instances', 0),
                    proc.get('max_instances'),
                    1 if proc.get('per_session') else 0,
                    proc.get('required_args'),
                    proc.get('source', 'YAML')
                ))
                stats['processes_imported'] += 1

            except Exception as e:
                stats['errors'] += 1
                logger.warning(f"Error importing {proc.get('process_name', 'unknown')}: {e}")

        conn.commit()
        logger.info(f"Imported {stats['processes_imported']} process expectations")

    finally:
        conn.close()

    return stats


def get_process_tree(yaml_path: Path = None) -> Dict[str, List[str]]:
    """
    Get the expected process tree as a parent -> children mapping.

    Args:
        yaml_path: Path to YAML file (optional)

    Returns:
        Dict mapping parent process to list of expected children
    """
    processes = load_process_expectations(yaml_path)
    tree = {}
    for proc in processes:
        parents = proc.get('valid_parents') or []
        for parent in parents:
            if parent not in tree:
                tree[parent] = []
            tree[parent].append(proc['process_name'])
    return tree


def get_system_processes(yaml_path: Path = None) -> List[str]:
    """Get list of processes that should run as SYSTEM."""
    processes = load_process_expectations(yaml_path)
    return [
        p['process_name'] for p in processes
        if p.get('user_type') == 'SYSTEM'
    ]


def get_user_processes(yaml_path: Path = None) -> List[str]:
    """Get list of processes that should run as user (not SYSTEM)."""
    processes = load_process_expectations(yaml_path)
    return [
        p['process_name'] for p in processes
        if p.get('user_type') == 'USER'
    ]
