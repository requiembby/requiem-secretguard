"""Generate clearly synthetic secrets in an ignored example folder."""
from pathlib import Path

root = Path(__file__).resolve().parents[1] / "demo-target"
root.mkdir(exist_ok=True)
(root / ".env").write_text("# SYNTHETIC TEST DATA. NOT REAL CREDENTIALS.\nSTRIPE_KEY=" + "sk_live_" + "A" * 24 + "\n", encoding="utf-8")
(root / "config.py").write_text("# SYNTHETIC TEST DATA. NOT REAL CREDENTIALS.\nMY_TOKEN = '" + "ghp_" + "B" * 36 + "'\n", encoding="utf-8")
print(f"Created synthetic demo target at {root}")
