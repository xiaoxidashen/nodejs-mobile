#!/usr/bin/env python3

import json
import sys
from typing import Any, Optional


def extract_compile_requests(stats: Any) -> Optional[int]:
    """从 sccache 统计 JSON 中提取 compile_requests。"""
    if not isinstance(stats, dict):
        return None

    direct_value = stats.get("compile_requests")
    if isinstance(direct_value, int):
        return direct_value

    nested_stats = stats.get("stats")
    if not isinstance(nested_stats, dict):
        return None

    nested_value = nested_stats.get("compile_requests")
    if isinstance(nested_value, int):
        return nested_value
    return None


def main() -> int:
    """从标准输入读取 JSON 并输出 compile_requests；不存在时输出空串。"""
    raw = sys.stdin.read().strip()
    if not raw:
        print("")
        return 0

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        print("")
        return 0

    compile_requests = extract_compile_requests(payload)
    print("" if compile_requests is None else compile_requests)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
