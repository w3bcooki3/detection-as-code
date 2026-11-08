"""Download the test logs listed in tests/logs.yml from EVTX-ATTACK-SAMPLES."""
import pathlib, subprocess, shutil, yaml
ROOT = pathlib.Path(__file__).resolve().parents[1]
src = ROOT / ".samples"
if not src.exists():
    subprocess.run(["git", "clone", "--depth", "1", "-q",
                    "https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES", str(src)], check=True)
dst = ROOT / "tests/logs"; dst.mkdir(parents=True, exist_ok=True)
for name, path in yaml.safe_load(open(ROOT / "tests/logs.yml")).items():
    shutil.copy(src / path, dst / name); print("fetched", name)
