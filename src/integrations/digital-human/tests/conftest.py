"""pytest 公共配置：把 skills/ 与 im/ 加入 import 路径（用 runtime/venv 的 Python 运行）。"""

import sys
from pathlib import Path

PKG = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PKG / "skills"))
sys.path.insert(0, str(PKG / "im"))
