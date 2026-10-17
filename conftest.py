"""让测试能直接 import 仓库根目录下的 probes / netwatch / analyzer。"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
