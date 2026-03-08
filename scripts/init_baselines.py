import json
import os
from pathlib import Path
import datetime

# Load static analysis results
# Update path to match your environment structure
# (assuming this script is in D:\Reverse ...\scripts\)
BASE_DIR = Path(__file__).resolve().parent.parent
# 静态分析结果目录
ANALYSIS_DIR = BASE_DIR / "collect" / "static_analysis"
# 输出目录
OUTPUT_DIR = BASE_DIR / "baseline_samples"

def get_latest_analysis_file():
    """获取最新的静态分析 JSON 文件"""
    if not ANALYSIS_DIR.exists():
        return None
    files = sorted(ANALYSIS_DIR.glob("static_analysis_*.json"), key=os.path.getmtime)
    if files:
        return files[-1]
    return None

def extract_source_values(node, keys_set):
    """
    递归从 Derivation 结构中提取 source value
    """
    if not node:
        return

    if isinstance(node, dict):
        if node.get("type") == "source":
            if "value" in node:
                keys_set.add(node["value"])

        # Recursive check suitable for derivation structure
        for key in ["input", "left", "right"]:
             if key in node:
                 extract_source_values(node[key], keys_set)

        if "args" in node and isinstance(node["args"], list):
            for arg in node["args"]:
                extract_source_values(arg, keys_set)

def generate_skeletons():
    """
    基于最新的静态分析结果生成统一的基线骨架文件。
    该文件将作为后续 Handler 开发、验证和安全性评估的核心输入。
    """
    static_analysis_file = get_latest_analysis_file()

    if not static_analysis_file:
        print(f"[Error] Static analysis directory or file not found in: {ANALYSIS_DIR}")
        print("Please run the static analysis phase first.")
        return

    print(f"[Info] Loading analysis from: {static_analysis_file.name}")
    try:
        with open(static_analysis_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except json.JSONDecodeError:
        print(f"[Error] Failed to parse JSON file: {static_analysis_file}")
        return

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    # 使用静态分析文件的时间戳来命名基线文件，保持关联性
    timestamp_str = static_analysis_file.stem.replace("static_analysis_", "")
    output_filename = f"baseline_skeletons_{timestamp_str}.json"
    output_path = OUTPUT_DIR / output_filename

    # 提取映射信息
    crypto_map = data.get("endpoint_crypto_map", {})
    endpoints = data.get("endpoints", [])

    print(f"[Info] Found {len(endpoints)} endpoints. Generating consolidated baseline file...")

    all_skeletons = []

    for ep in endpoints:
        url = ep.get("url")
        if not url:
            continue

        # 生成唯一 ID (Moved to top)
        path_part = url.split('/')[-1].split('?')[0] # 简单的文件名作为ID基础
        endpoint_id = path_part.replace('.php', '')

        method = ep.get("method", "POST")
        trigger_func = ep.get("trigger_function")

        # 获取加密详情
        ep_details = crypto_map.get(url, {})
        algos = ep_details.get("algorithms", [])

        # 深入提取详细的执行流（Execution Flow）
        # 将静态分析中的 operations -> details 展平为有序步骤
        raw_operations = ep_details.get("operations", [])
        execution_flow = []

        # 存储推断出的 payload key (Schema)
        inferred_payload_keys = set()

        # 1. First pass: Collect all potential keys from derivations in all steps
        for op_group in raw_operations:
             for detail in op_group.get("details", []):
                 # From derivation
                 if "derivation" in detail:
                     extract_source_values(detail["derivation"], inferred_payload_keys)
                 # From DataStructure inferred_keys
                 if detail.get("operation") == "DataStructure" and "inferred_keys" in detail:
                     inferred_payload_keys.update(detail["inferred_keys"])
                 # From Packing Info (NEW)
                 if detail.get("operation") == "pack" and "info" in detail:
                     packing_info = detail["info"]
                     if "value_derivations" in packing_info:
                         for key, derivation in packing_info["value_derivations"].items():
                             extract_source_values(derivation, inferred_payload_keys)

        for op_group in raw_operations:
            # 这是一个算法组（如 JSEncrypt RSA 操作组）
            library = op_group.get("library")
            algorithm = op_group.get("algorithm")

            # 遍历该组内的具体细节步骤
            for detail in op_group.get("details", []):
                op_type = detail.get("operation")

                # 特殊处理：如果发现了 DataStructure 类型的 operation，这是 Payload 结构推断结果
                if op_type == "DataStructure":
                    # handled in first pass
                    continue

                # 提取 resolved_value 作为 runtime_args
                runtime_args = {}
                resolved_val = detail.get("resolved_value")

                if op_type == "setkey":
                    if resolved_val:
                        # 将硬编码的 key 填入 runtime_args
                        if algorithm == "RSA":
                            runtime_args["public_key"] = resolved_val
                        else:
                            runtime_args["key"] = resolved_val
                    else:
                        pass

                elif op_type == "setiv" and resolved_val:
                    runtime_args["iv"] = resolved_val

                # NEW: Capture Packing Info
                elif op_type == "pack" and "info" in detail:
                    runtime_args["packing_info"] = detail["info"]

                # NEW: Capture Derivation Logic
                elif op_type.startswith("derive_") and "derivation" in detail:
                    runtime_args["derivation"] = detail["derivation"]

                step = {
                    "step_type": op_type, # e.g., "init", "setkey", "encrypt"
                    "library": library,
                    "algorithm": algorithm,
                    "line": detail.get("line"),
                    "context": detail.get("context", "").strip(),
                    # 预留给 Handler 运行时填入具体参数的槽位
                    "runtime_args": runtime_args
                }

                # Forward output variable if available
                if "output_variable" in detail:
                    step["output_variable"] = detail["output_variable"]

                execution_flow.append(step)

        # 提取相关操作代码行作为开发提示 (Hints)
        ops = ep_details.get("operations", [])
        hints = []
        for op in ops:
            details = op.get("details", [])
            for d in details:
                line = d.get('line')
                ctx = d.get('context', '').strip()
                if line and ctx:
                    hints.append(f"Line {line}: {ctx}")

        # KEY FIX: Sort execution flow by line number
        # Corrects the issue where packing might appear first or encryption steps are out of order
        execution_flow.sort(key=lambda x: x.get("line", 0))

        # 构建单个 API 的基线结构

        # 构造预填的 payload
        initial_payload = {}
        if inferred_payload_keys:
            print(f"[Info] [{endpoint_id}] Inferred payload keys: {inferred_payload_keys}")
            for k in inferred_payload_keys:
                initial_payload[k] = "<Fill Value>"
        else:
             initial_payload = {"_comment": "Fill your payload here"}

        skeleton = {
            "meta": {
                "id": endpoint_id,
                "url": url,
                "method": method,
                "trigger_function": trigger_func,
                "crypto_algorithms": algos,
                "source_analysis_file": str(static_analysis_file.name),
                "generated_at": datetime.datetime.now().isoformat(),
                "execution_flow": execution_flow,
                "hints": hints
            },
            "status": "PENDING_PAYLOAD",
            "request": {
                "payload": initial_payload,
                "headers": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Verified/1.0"
                }
            },
            "validation": {
                "verified": False,
                "last_run": None,
                "captured_ciphertext": None,
                "handler_ciphertext": None,
                "comparison_result": None
            }
        }

        all_skeletons.append(skeleton)

    if not all_skeletons:
        print("[Warn] No endpoints found to generate skeletons.")
        return

    # 将所有骨架写入同一个文件
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(all_skeletons, f, indent=2, ensure_ascii=False)

    print(f"\n[Success] Generated consolidated baseline with {len(all_skeletons)} entries.")
    print(f"File location: {output_path}")
    print("Next Step: Manually or automatically populate 'request.payload' in this file before running handlers.")

if __name__ == "__main__":
    generate_skeletons()
