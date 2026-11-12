import json

from guardbench import EvidenceLog, verify_chain
from guardbench.cli import main


def _log(path, n=3):
    log = EvidenceLog(path)
    for i in range(n):
        log.write(principal="user:a", agent="agent:x", stage="input", decision="allow", reason=str(i))
    return log


def test_intact_chain_verifies(tmp_path):
    path = tmp_path / "e.jsonl"
    log = _log(path)
    assert verify_chain(path, log.head) == (True, "3 records verified")


def test_edited_record_is_detected(tmp_path):
    path = tmp_path / "e.jsonl"
    _log(path)
    lines = path.read_text().splitlines()
    record = json.loads(lines[1])
    record["decision"] = "block"
    path.write_text("\n".join([lines[0], json.dumps(record), lines[2]]) + "\n")
    ok, message = verify_chain(path)
    assert not ok and "record 2" in message


def test_deleted_middle_record_is_detected(tmp_path):
    path = tmp_path / "e.jsonl"
    _log(path)
    lines = path.read_text().splitlines()
    path.write_text("\n".join([lines[0], lines[2]]) + "\n")
    assert not verify_chain(path)[0]


def test_truncation_needs_the_anchored_head(tmp_path):
    path = tmp_path / "e.jsonl"
    log = _log(path)
    lines = path.read_text().splitlines()
    path.write_text("\n".join(lines[:2]) + "\n")
    assert verify_chain(path)[0]  # the remaining chain is internally consistent
    assert not verify_chain(path, log.head)[0]  # the anchor exposes the missing record


def test_log_resumes_from_existing_file(tmp_path):
    path = tmp_path / "e.jsonl"
    _log(path, 2)
    EvidenceLog(path).write(principal="user:a", agent="agent:x", stage="output", decision="block")
    assert verify_chain(path)[0]


def test_cli_verify_log(tmp_path, capsys):
    path = tmp_path / "e.jsonl"
    _log(path)
    assert main(["verify-log", str(path)]) == 0
    assert capsys.readouterr().out.startswith("OK")
