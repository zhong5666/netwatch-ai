"""让测试能直接 import 仓库根目录下的 probes / netwatch / analyzer，以及 tools/ 下的开发工具。"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
for path in (ROOT, ROOT / "tools"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))
