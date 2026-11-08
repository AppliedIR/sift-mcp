"""Run the RAG version paths in a fresh process on a scratch copy of the package.

Used by test_rag_versions.py, test_rag_bundle_state.py and
test_rag_licences.py; not a test module itself. The test puts a scratch copy
of the package first on sys.path, so every file the package reads under its
own data dir is the copy's, never the installed tree's. The version lookups
are stubbed at their functions, every URL fetch is recorded and answered only
from fixture files, the bundle install's release lookup is answered with local
file URLs, and the embedding model is a stand-in, so nothing here reaches the
network or loads a model.

Usage: python _rag_versions_probe.py <spec.json> <out.json>
"""

from __future__ import annotations

import contextlib
import io
import json
import logging
import runpy
import subprocess
import sys
import traceback
import types
from dataclasses import asdict
from pathlib import Path


def _stand_in_model() -> types.ModuleType:
    """A sentence_transformers stand-in: fixed small vectors, no model files."""
    import numpy as np

    class SentenceTransformer:
        def __init__(self, name: str, *args, **kwargs) -> None:
            self.name = name

        def encode(self, texts, *args, **kwargs):
            if isinstance(texts, str):
                return np.array([1.0, float(len(texts) % 5), 0.5, 0.25])
            return np.array([[1.0, float(len(t) % 5), 0.5, 0.25] for t in texts])

    mod = types.ModuleType("sentence_transformers")
    mod.SentenceTransformer = SentenceTransformer
    return mod


def _tip(bare: str, branch: str) -> str:
    out = subprocess.run(
        ["git", "-C", bare, "rev-parse", f"refs/heads/{branch}"],
        capture_output=True,
        text=True,
        check=True,
    )
    return out.stdout.strip()


def _advance(bare: str, branch: str) -> str:
    """Land one more commit on a fixture branch, as a push between two reads."""
    parent = _tip(bare, branch)
    tree = subprocess.run(
        ["git", "-C", bare, "rev-parse", f"{parent}^{{tree}}"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    new = subprocess.run(
        ["git", "-C", bare, "commit-tree", tree, "-p", parent, "-m", "later"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    subprocess.run(
        ["git", "-C", bare, "update-ref", f"refs/heads/{branch}", new], check=True
    )
    return new


class Lookups:
    """Stubs for get_latest_commit, get_latest_release and get_feed_version.

    Each table maps a repo (or feed URL) to an answer: a string, None, or a
    rule: {"raise": true}, {"tip": bare} (the branch asked, read from the
    fixture), {"advance": bare} (first land a commit on the branch asked).
    """

    def __init__(self, spec: dict) -> None:
        self.spec = spec
        self.calls: list[list] = []

    def _answer(self, kind: str, key: str, branch: str | None):
        self.calls.append([kind, key, branch])
        table = self.spec[kind]
        answer = table.get(key, table.get("*"))
        if isinstance(answer, dict):
            if answer.get("raise"):
                raise RuntimeError(f"stubbed {kind} lookup failure")
            if "advance" in answer and not answer.get("done"):
                answer["done"] = True
                return _advance(answer["advance"], branch or "main")[:12]
            bare = answer.get("tip") or answer.get("advance")
            return _tip(bare, branch or "main")[:12]
        return answer

    def commit(self, repo: str, branch: str):
        return self._answer("commit", repo, branch)

    def release(self, repo: str):
        return self._answer("release", repo, None)

    def feed(self, url: str):
        return self._answer("feed", url, None)

    def install(self, sources) -> None:
        if "commit" in self.spec:
            sources.get_latest_commit = self.commit
        if "release" in self.spec:
            sources.get_latest_release = self.release
        if "feed" in self.spec:
            sources.get_feed_version = self.feed


def _logged(fn):
    """Run fn with stdout and the root logger writing to one buffer, in the
    message-only format the build sets up for itself."""
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    handler.setFormatter(logging.Formatter("%(message)s"))
    root.addHandler(handler)
    root.setLevel(logging.INFO)
    out: dict = {"rc": None, "error": None}
    try:
        with contextlib.redirect_stdout(buf):
            value = fn()
        out["rc"] = value if isinstance(value, int) else 0
        out["value"] = value if isinstance(value, (dict, list, str)) else None
    except SystemExit as e:
        out["rc"] = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
    except BaseException:
        out["error"] = traceback.format_exc(limit=4).strip().splitlines()[-1]
    finally:
        for h in list(root.handlers):
            root.removeHandler(h)
    out["stdout"] = buf.getvalue()
    return out


def _last_json(stdout: str):
    """The JSON object status --json printed, among any log lines."""
    decoder = json.JSONDecoder()
    starts = [0] if stdout.startswith("{") else []
    starts += [i + 1 for i, ch in enumerate(stdout) if ch == "\n"]
    for start in starts:
        if stdout.startswith("{", start):
            try:
                return decoder.raw_decode(stdout, start)[0]
            except ValueError:
                continue
    return None


def _make_index(data_dir: str, count: int = 1) -> None:
    import chromadb

    client = chromadb.PersistentClient(path=str(Path(data_dir) / "chroma"))
    col = client.create_collection("ir_knowledge", metadata={"hnsw:space": "cosine"})
    step = 5000
    for start in range(0, count, step):
        ids = range(start, min(start + step, count))
        col.add(
            ids=[f"fixture_{i}" for i in ids],
            documents=[f"A fixture record {i}." for i in ids],
            embeddings=[[1.0, float(i % 7), 0.5, 0.25] for i in ids],
            metadatas=[{"source": "fixture"} for _ in ids],
        )


def _release(assets_dir: str, names) -> dict:
    """A release whose assets are local files, so the download reads them."""
    return {
        "tag_name": "rag-index-fixture",
        "assets": [
            {"name": n, "url": (Path(assets_dir) / n).resolve().as_uri()} for n in names
        ],
    }


def _main_with(argv: list[str], fn) -> None:
    saved = sys.argv
    sys.argv = argv
    try:
        fn()
    finally:
        sys.argv = saved


def main() -> int:
    spec_path, out_path = sys.argv[1:3]
    spec = json.loads(Path(spec_path).read_text(encoding="utf-8"))
    sys.modules["sentence_transformers"] = _stand_in_model()

    import rag_mcp
    from rag_mcp import sources

    pkg_src = Path(spec["pkg_src"]).resolve()
    where = Path(rag_mcp.__file__).resolve()
    if pkg_src not in where.parents:
        Path(out_path).write_text(
            json.dumps({"probe_error": f"rag_mcp imported from {where}"}),
            encoding="utf-8",
        )
        return 3

    if spec.get("replace_sources"):
        sources.SOURCES.clear()
    for fx in spec.get("sources", []):
        sources.SOURCES[fx["name"]] = sources.SourceConfig(
            name=fx["name"],
            description=f"Fixture {fx['name']}",
            source_type=fx["source_type"],
            repo=fx["repo"],
            branch=fx.get("branch", "main"),
            parser=fx.get("parser", "default"),
            paths=[],
        )

    requests: list[str] = []
    responses = spec.get("responses", [])

    def fetch_url(url, headers=None, max_bytes=None, max_retries=None):
        requests.append(url)
        for prefix, path in responses:
            if url.startswith(prefix):
                return Path(path).read_bytes()
        return None

    sources.fetch_url = fetch_url
    lookups = Lookups(spec.get("lookups", {}))
    lookups.install(sources)

    results: list[dict] = []
    for op in spec["ops"]:
        kind = op["op"]
        mark = len(requests)
        if kind == "index":
            res = _logged(lambda op=op: _make_index(op["dir"], op.get("count", 1)))
        elif kind == "pack":
            from rag_mcp.scripts import build_release

            build_release.MIN_RECORD_COUNT = 0
            argv = ["build_release", "--skip-build", "--output-dir", op["out"]]
            res = _logged(lambda argv=argv: _main_with(argv, build_release.main))
        elif kind == "release":
            # The full release path (fetch, strict build, pack) over fixture
            # sources, with the record floor lowered to the fixture's size as
            # the pack op lowers it.
            from rag_mcp.scripts import build_release

            build_release.MIN_RECORD_COUNT = op.get("floor", 1)
            argv = ["build_release", "--output-dir", op["out"]]
            res = _logged(lambda argv=argv: _main_with(argv, build_release.main))
        elif kind == "install":
            from rag_mcp.scripts import download_index

            if op.get("verify") is False:
                # A fixture build is far below the installed index's record
                # floor, as the release op's floor is lowered for the same
                # reason; everything else in the install runs as shipped.
                download_index._verify_index = lambda d: True
            release = _release(op["assets"], download_index.ASSETS)
            download_index._fetch_release = lambda tag="latest", r=release: r
            argv = ["download_index", *op["argv"]]
            res = _logged(lambda argv=argv: _main_with(argv, download_index.main))
        elif kind == "sync":

            def sync(op=op):
                return asdict(sources.sync_source(op["name"], force=op["force"]))

            res = _logged(sync)
        elif kind == "latest":
            config = sources.SOURCES[op["name"]]
            res = _logged(lambda config=config: sources.get_latest_version(config))
        elif kind == "check":
            res = _logged(lambda: [asdict(s) for s in sources.check_source_updates()])
        elif kind == "build":

            def run_build(op=op):
                saved = sys.argv
                sys.argv = ["rag_mcp.build", *op["argv"]]
                try:
                    runpy.run_module("rag_mcp.build", run_name="__main__")
                finally:
                    sys.argv = saved

            res = _logged(run_build)
        elif kind == "build_fn":
            from rag_mcp import build

            def run_build_fn(op=op):
                kwargs = dict(op["kwargs"])
                for key in ("data_dir", "knowledge_dir"):
                    if kwargs.get(key):
                        kwargs[key] = Path(kwargs[key])
                return asdict(build.build(**kwargs))

            res = _logged(run_build_fn)
        elif kind == "status":
            from rag_mcp import status

            def run_status(op=op):
                saved = sys.argv
                sys.argv = ["status", *op["argv"]]
                try:
                    return status.main()
                finally:
                    sys.argv = saved

            res = _logged(run_status)
            res["json"] = _last_json(res["stdout"])
        else:
            raise ValueError(f"unknown op {kind}")
        res["op"] = kind
        res["requests"] = requests[mark:]
        results.append(res)

    Path(out_path).write_text(
        json.dumps({"ops": results, "lookups": lookups.calls}, indent=2),
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
