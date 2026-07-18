import json
import os
import subprocess


def test_manifest_reports_name_and_version(wasm_path):
    out = subprocess.run(
        [os.environ.get("ACT", "act"), "inspect", "component-manifest", str(wasm_path)],
        capture_output=True, text=True, check=True,
    ).stdout
    manifest = json.loads(out)
    assert manifest["std"]["name"] == "crypto"
    assert isinstance(manifest["std"]["version"], str)
