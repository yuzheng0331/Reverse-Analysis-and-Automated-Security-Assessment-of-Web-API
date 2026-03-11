#!/usr/bin/env python3
"""
最终答辩版统一入口。

对外推荐直接从项目根目录运行 `python main.py`。
内部仍由 `phases/run_full_pipeline.py` 负责阶段编排，
再进一步调用 `collect/`、`scripts/`、`handlers/`、`assess/`、`runtime/` 中的核心实现。
"""

from phases.run_full_pipeline import main


if __name__ == "__main__":
    main()
