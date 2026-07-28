#!/usr/bin/env python3
"""render_test_report.py - 汇总 SOCI SGX SDK 的测试/基准产物，渲染 Markdown + JSON 报告。

仅依赖 Python 标准库。输入:
  --project    项目根目录
  --out        报告输出目录 (含 results/*.json 与 report-artifacts/)
  --artifacts  generate_test_report.sh 写入的 artifacts 目录 (env.txt, steps.tsv, skips.tsv, *.log)
"""
import argparse
import glob
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

# 模式 -> ctest preset -> 构建目录
MODE_PRESET = {
    "off": ("off-debug", "build/off-debug"),
    "sim": ("sim-release", "build/sim-release"),
    "hw": ("hw-release", "build/hw-release"),
}
MODE_LABEL = {"off": "OFF", "sim": "SIM", "hw": "HW"}

# versions.lock 键 -> (展示名, env.txt 实际键)
VERSION_MAP = [
    ("ubuntu", "Ubuntu 基础镜像", "os_release"),
    ("architecture", "架构", None),
    ("gcc", "GCC", "gcc_version"),
    ("cmake", "CMake", "cmake_version"),
    ("python", "Python", "python3_version"),
    ("openjdk", "OpenJDK", "java_version"),
    ("gmp", "GMP", None),
    ("openssl", "OpenSSL", "openssl_version"),
    ("intel_sgx_sdk", "Intel SGX SDK", "sgx_sdk_present"),
    ("pybind11", "pybind11", None),
]


def read_kv(path):
    """读取 key=value 文件为 dict (值保留首个 = 之后全部内容)。"""
    d = {}
    try:
        for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                d[k.strip()] = v
    except FileNotFoundError:
        pass
    return d


def read_tsv(path):
    rows = []
    try:
        for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            rows.append(line.split("\t"))
    except FileNotFoundError:
        pass
    return rows


def read_versions_lock(project):
    return read_kv(Path(project) / "versions.lock")


# ---- 测试结果解析 ------------------------------------------------------------

TEST_LINE_RE = re.compile(
    r"^(\d+)/(\d+)\s+Test\s+#\d+:\s*(\S+)\s+\.+\s*(Passed|Failed|Not Run)\b\s*(.*)$",
    re.IGNORECASE,
)
SUMMARY_RE = re.compile(
    r"(\d+)%\s*tests?\s+passed,?\s*(\d+)\s*tests?\s+failed\s+out\s+of\s+(\d+)",
    re.IGNORECASE,
)


def parse_ctest_log(log_path):
    """解析 ctest 输出日志(默认或 --verbose) -> (tests, summary)。"""
    tests = []
    summary = None
    try:
        text = Path(log_path).read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return tests, summary
    for line in text.splitlines():
        m = TEST_LINE_RE.match(line.strip())
        if m:
            name = m.group(3)
            status = m.group(4).lower()
            if status == "not run":
                status = "notrun"
            tail = m.group(5)
            t = None
            tm = re.search(r"([\d.]+)\s*sec", tail)
            if tm:
                try:
                    t = float(tm.group(1))
                except ValueError:
                    t = None
            tests.append({"name": name, "status": status, "time_s": t})
        sm = SUMMARY_RE.search(line)
        if sm:
            summary = {
                "pct": int(sm.group(1)),
                "failed": int(sm.group(2)),
                "total": int(sm.group(3)),
            }
    return tests, summary


def parse_test_xml(xml_path):
    """解析 CTest Test.xml -> tests 列表。"""
    tests = []
    try:
        tree = ET.parse(xml_path)
    except (ET.ParseError, FileNotFoundError, OSError):
        return tests
    root = tree.getroot()
    for t in root.iter("Test"):
        status = (t.get("Status") or "").lower()
        name = (t.findtext("Name") or "").strip()
        if not name:
            continue
        time_s = None
        for nm in t.iter("NamedMeasurement"):
            if (nm.get("name") or "") == "Execution Time":
                try:
                    time_s = float((nm.text or "").strip())
                except ValueError:
                    time_s = None
        tests.append({"name": name, "status": status, "time_s": time_s})
    return tests


def newest_test_xml(build_dir):
    matches = sorted(glob.glob(os.path.join(build_dir, "Testing", "*", "Test.xml")),
                     key=lambda p: os.path.getmtime(p) if os.path.exists(p) else 0,
                     reverse=True)
    return matches[0] if matches else None


def parse_lasttest_log(log_path):
    """解析 ctest 始终写入的 Testing/Temporary/LastTest.log -> tests 列表。

    每个用例块形如:
      1/1 Testing: soci_tests
      ...
      Test time =   0.24 sec
      Test Passed.   (或 Test Failed.)
    """
    tests = []
    try:
        text = Path(log_path).read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return tests
    cur = None
    for line in text.splitlines():
        m = re.match(r"^\d+/\d+\s+Testing:\s*(\S+)", line)
        if m:
            if cur:
                tests.append(cur)
            cur = {"name": m.group(1), "status": "unknown", "time_s": None}
            continue
        if cur is not None:
            tm = re.match(r"^Test time\s*=\s*([\d.]+)\s*sec", line)
            if tm:
                try:
                    cur["time_s"] = float(tm.group(1))
                except ValueError:
                    pass
                continue
            sm = re.match(r"^Test (Passed|Failed)\.", line)
            if sm:
                cur["status"] = sm.group(1).lower()
    if cur:
        tests.append(cur)
    return tests


def gather_tests(mode, project, steps_for_mode):
    """返回 (tests, source)。优先用本次执行的 test 步骤日志(保证新鲜；docker 运行
    在宿主上无 Test.xml)，回退到 build 目录下的 Test.xml (collect-only 时)。"""
    _, build_dir = MODE_PRESET[mode]
    # 1) 本次执行的 test / build-test 步骤日志(新鲜)
    for step, _status, log in steps_for_mode:
        if step in ("test", "build-test"):
            ts, summary = parse_ctest_log(log)
            if ts:
                return ts, f"ctest 日志 ({os.path.relpath(log, project)})"
            if summary:
                return [], f"ctest 汇总 ({os.path.relpath(log, project)})"
    # 2) 回退: build 目录下最新的 Test.xml
    xml_path = newest_test_xml(os.path.join(project, build_dir))
    if xml_path:
        ts = parse_test_xml(xml_path)
        if ts:
            return ts, f"Test.xml ({os.path.relpath(xml_path, project)})"
    # 3) 回退: ctest 始终写入的 LastTest.log (collect-only 时主要来源)
    lt_path = os.path.join(project, build_dir, "Testing", "Temporary", "LastTest.log")
    if os.path.exists(lt_path):
        ts = parse_lasttest_log(lt_path)
        if ts:
            return ts, f"LastTest.log ({os.path.relpath(lt_path, project)})"
    return [], None


# ---- 基准 / 产物解析 ---------------------------------------------------------

def load_benchmarks(out_dir):
    """加载 results 下所有基准 JSON，按文件归类。"""
    benches = []
    patterns = ["benchmark-*.json", "keygen-*.json", "cp-csp-benchmark-*.json"]
    for pat in patterns:
        for path in sorted(glob.glob(os.path.join(out_dir, pat))):
            try:
                data = json.loads(Path(path).read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                data = {"_error": "无法解析 JSON"}
            benches.append({"file": os.path.basename(path), "path": path, "data": data})
    return benches


def bench_mode(file_name):
    if "-off-" in file_name:
        return "off"
    if "-sim-" in file_name:
        return "sim"
    if "-hw-" in file_name:
        return "hw"
    return "unknown"


def load_build_manifests(project):
    manifests = []
    for path in sorted(glob.glob(os.path.join(project, "build", "*", "build-manifest.json"))):
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        data["_dir"] = os.path.relpath(os.path.dirname(path), project)
        manifests.append(data)
    return manifests


def list_dist(project):
    d = Path(project) / "dist"
    files = []
    if d.is_dir():
        for p in sorted(d.iterdir()):
            if p.is_file():
                files.append({"name": p.name, "size": p.stat().st_size})
    return files


# ---- 渲染辅助 ----------------------------------------------------------------

def md_escape(v):
    """转义表格单元格中的 | 与换行，避免破坏 markdown 表格。"""
    return str(v).replace("|", "\\|").replace("\n", " ")


def md_table(headers, rows):
    if not rows:
        return "_(无数据)_\n"
    out = []
    out.append("| " + " | ".join(md_escape(h) for h in headers) + " |")
    out.append("| " + " | ".join("---" for _ in headers) + " |")
    for r in rows:
        out.append("| " + " | ".join(md_escape(c) for c in r) + " |")
    return "\n".join(out) + "\n"


def fmt_ms(v):
    if v is None:
        return "—"
    try:
        return f"{float(v):.3f}"
    except (TypeError, ValueError):
        return str(v)


def fmt_bytes(n):
    try:
        n = float(n)
    except (TypeError, ValueError):
        return str(n)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def status_badge(s):
    s = (s or "").lower()
    if s in ("passed", "ok", "0"):
        return "✅ 通过"
    if s in ("failed", "fail"):
        return "❌ 失败"
    if s in ("skipped", "skip"):
        return "⏭ 跳过"
    if s in ("notrun", "not run"):
        return "➖ 未运行"
    if s in ("unknown", ""):
        return "❔ 未知"
    return s


# ---- 主报告构建 --------------------------------------------------------------

def build_report(project, out_dir, artifacts):
    project = Path(project).resolve()
    out_dir = Path(out_dir).resolve()
    artifacts = Path(artifacts).resolve()

    env = read_kv(artifacts / "env.txt")
    versions = read_versions_lock(project)
    steps = read_tsv(artifacts / "steps.tsv")  # [mode, step, status, log]
    skips = read_tsv(artifacts / "skips.tsv")  # [mode, reason]

    steps_by_mode = {}
    for row in steps:
        if len(row) >= 4:
            steps_by_mode.setdefault(row[0], []).append((row[1], row[2], row[3]))
    skip_reasons = {row[0]: row[1] for row in skips if len(row) >= 2}

    modes_data = {}
    for mode in ("off", "sim", "hw"):
        preset, build_dir = MODE_PRESET[mode]
        msteps = steps_by_mode.get(mode, [])
        executed = bool(msteps)
        # 仅当模式在本报告范围内(有执行步骤，或有跳过记录如 collect-only/无设备)才汇总其数据；
        # 否则(未在 --modes 中指定)不拉取已有产物，避免把旧运行结果误当本次结果。
        in_scope = executed or (mode in skip_reasons)
        if in_scope:
            tests, source = gather_tests(mode, str(project), msteps)
        else:
            tests, source = [], None
        from_existing = (not executed) and bool(tests)
        passed = sum(1 for t in tests if t["status"] == "passed")
        failed = sum(1 for t in tests if t["status"] == "failed")
        notrun = sum(1 for t in tests if t["status"] == "notrun")
        any_step_fail = any(s != "0" for _step, s, _log in msteps)
        any_step_ok = any(s == "0" for _step, s, _log in msteps)

        if not in_scope:
            mstatus = "notrun"
        elif tests and failed:
            mstatus = "failed"
        elif tests and passed:
            mstatus = "passed"
        elif any_step_fail:
            mstatus = "failed"
        elif any_step_ok:
            mstatus = "passed"  # 步骤成功但无逐项测试数据(如仅 benchmark)
        elif mode in skip_reasons:
            mstatus = "skipped"
        else:
            mstatus = "unknown"

        modes_data[mode] = {
            "label": MODE_LABEL[mode],
            "preset": preset,
            "status": mstatus,
            "executed": executed,
            "in_scope": in_scope,
            "from_existing": from_existing,
            "skip_reason": skip_reasons.get(mode),
            "tests": tests,
            "test_source": source,
            "passed": passed,
            "failed": failed,
            "notrun": notrun,
            "steps": [{"step": s, "status": st, "log": log} for s, st, log in msteps],
            "any_step_fail": any_step_fail,
        }

    benches = load_benchmarks(out_dir)
    manifests = load_build_manifests(str(project))
    dist_files = list_dist(str(project))

    # 总体结论
    any_fail = any(m["status"] == "failed" for m in modes_data.values())
    any_pass = any(m["status"] == "passed" for m in modes_data.values())
    if any_fail:
        verdict = "FAIL"
    elif any_pass:
        verdict = "PASS"
    else:
        verdict = "UNKNOWN"

    report = {
        "meta": {
            "project": "soci-sgx-sdk",
            "generated_at": env.get("date_iso", "unknown"),
            "host": env.get("host", "unknown"),
            "generator": "scripts/generate_test_report.sh + scripts/render_test_report.py",
            "git_commit": env.get("git_commit", "none"),
            "git_branch": env.get("git_branch", "none"),
        },
        "verdict": verdict,
        "environment": {
            "pinned": versions,
            "actual": env,
        },
        "modes": modes_data,
        "benchmarks": [{"file": b["file"], "data": b["data"]} for b in benches],
        "build_manifests": manifests,
        "dist": {
            "files": dist_files,
            "image_id": env.get("dist_image_id", "none"),
            "archive_sha256": env.get("dist_archive_sha256", "none"),
            "sha256_verify": env.get("dist_sha256_verify", "skipped"),
            "docker_images_soci": env.get("docker_images_soci", "none"),
        },
    }
    return report


# ---- Markdown 渲染 -----------------------------------------------------------

def render_md(r):
    L = []
    m = r["meta"]
    L.append("# SOCI SGX SDK 测试报告\n")
    L.append(f"- 生成时间: `{m['generated_at']}`")
    L.append(f"- 主机: `{m['host']}`")
    L.append(f"- Git: `{m['git_commit']}` @ `{m['git_branch']}`")
    L.append(f"- 生成器: `{m['generator']}`\n")

    L.append("## 总体结论\n")
    verdict_map = {"PASS": "✅ **PASS** — 全部已执行测试通过",
                   "FAIL": "❌ **FAIL** — 存在失败的测试或步骤",
                   "UNKNOWN": "❔ **UNKNOWN** — 无已执行测试数据"}
    any_executed = any(md["executed"] for md in r["modes"].values())
    any_existing = any(md["from_existing"] for md in r["modes"].values())
    if r["verdict"] == "PASS" and not any_executed and any_existing:
        L.append("✅ **PASS** - 现有测试数据均通过(基于已有产物，非本次运行)\n")
    elif r["verdict"] == "PASS" and not any_executed:
        L.append("❔ **UNKNOWN** - 无已执行测试数据，也无可用已有产物\n")
    else:
        L.append(verdict_map.get(r["verdict"], r["verdict"]) + "\n")
    if not any_executed and any_existing:
        L.append("\n> ℹ️ 本报告未执行任何测试步骤(可能为 `--collect-only`)；"
                 "测试数据来自已有产物，非本次运行结果。\n")

    L.append("### 模式覆盖\n")
    rows = []
    for mode in ("off", "sim", "hw"):
        md = r["modes"][mode]
        if md["status"] == "notrun":
            note = "未在 --modes 中指定"
        elif md["status"] == "skipped":
            note = md["skip_reason"] or ""
        else:
            parts = []
            if md["tests"]:
                parts.append(f"{md['passed']} 通过 / {md['failed']} 失败 / {md['notrun']} 未运行")
            if md["from_existing"]:
                parts.append("来自已有产物(非本次运行)")
            if md["any_step_fail"]:
                parts.append("存在失败步骤")
            note = "；".join(parts) if parts else ("已执行" if md["executed"] else "未执行")
        rows.append([MODE_LABEL[mode], status_badge(md["status"]), note])
    L.append(md_table(["模式", "状态", "说明"], rows))
    L.append("")

    # 环境
    L.append("## 环境\n")
    L.append("### 固定版本 (`versions.lock`) vs 本机实测\n")
    rows = []
    for key, label, actual_key in VERSION_MAP:
        pinned = r["environment"]["pinned"].get(key, "—")
        actual = "—"
        if actual_key:
            actual = r["environment"]["actual"].get(actual_key, "—")
            if actual_key == "sgx_sdk_present":
                actual = "已安装" if actual == "yes" else ("未安装" if actual == "no" else actual)
        rows.append([label, pinned, actual])
    L.append(md_table(["组件", "固定版本", "本机实测"], rows))
    L.append("")
    L.append("### SGX / 设备 / 工具链\n")
    env = r["environment"]["actual"]
    rows = [
        ["操作系统", env.get("os_release", "—")],
        ["内核", env.get("uname", "—")],
        ["CPU 核数", env.get("nproc", "—")],
        ["SGX SDK 路径", env.get("sgx_sdk_env", "—") + f" (存在: {env.get('sgx_sdk_present','—')})"],
        ["SGX Enclave 设备", env.get("sgx_enclave_device", "—")],
        ["SGX Provision 设备", env.get("sgx_provision_device", "—")],
        ["CPU sgx 标志", env.get("cpu_sgx_flag", "—")],
        ["Docker", env.get("docker_version", "—")],
        ["Docker Compose", env.get("docker_compose", "—")],
        ["gcc-11 路径", env.get("gcc11_path", "—")],
        ["g++-11 路径", env.get("gpp11_path", "—")],
    ]
    L.append(md_table(["项", "值"], rows))
    L.append("")

    # 测试结果
    L.append("## 测试结果\n")
    for mode in ("off", "sim", "hw"):
        md = r["modes"][mode]
        L.append(f"### {MODE_LABEL[mode]} 模式  —  {status_badge(md['status'])}\n")
        if md["status"] == "notrun":
            L.append(f"未在本次 `--modes` 中指定；如需包含，请加 `--modes ...,{mode},...`。\n")
            continue
        if md["status"] == "skipped":
            L.append(f"跳过原因: {md['skip_reason']}\n")
            continue
        if not md["executed"] and not md["tests"]:
            L.append("未执行，且无已有产物。\n")
            continue
        L.append(f"- 数据来源: `{md['test_source'] or '无'}`")
        if md["from_existing"]:
            L.append("- ⚠️ 来自已有产物，非本次运行结果")
        L.append(f"- 用例统计: {md['passed']} 通过 / {md['failed']} 失败 / {md['notrun']} 未运行")
        L.append(f"- 执行步骤: {len(md['steps'])} 个"
                 + ("（含失败步骤）" if md['any_step_fail'] else ""))
        if md["steps"]:
            srows = []
            for s in md["steps"]:
                srows.append([s["step"], status_badge(s["status"])])
            L.append("\n**步骤:**\n")
            L.append(md_table(["步骤", "状态"], srows))
        if md["tests"]:
            trows = []
            for t in md["tests"]:
                t = t  # noqa
                trows.append([
                    t["name"],
                    status_badge(t["status"]),
                    f"{t['time_s']:.4f}" if t["time_s"] is not None else "—",
                ])
            L.append("\n**用例:**\n")
            L.append(md_table(["用例", "状态", "耗时 (s)"], trows))
        L.append("")

    # 性能基准
    L.append("## 性能基准\n")
    if not r["benchmarks"]:
        L.append("_(未发现 results/*.json 基准产物)_\n")
    else:
        L.append("> 说明: OFF 基准中的 SMUL/SCMP/SABS/SDIV 为 `experimental_reference_only`，"
                 "仅用于 API/正确性/回归，不代表 SGX 或生产协议性能；SIM 数据不代表 HW 性能。详见 `docs/BENCHMARK.md`。\n")
        for b in r["benchmarks"]:
            L.append(f"### `{b['file']}`\n")
            data = b["data"]
            if isinstance(data, dict) and isinstance(data.get("results"), list):
                meta = {k: v for k, v in data.items() if k != "results"}
                if meta:
                    for k, v in meta.items():
                        L.append(f"- {k}: `{v}`")
                    L.append("")
                results = data["results"]
                # 自适应列: 收集所有结果项的键，按优先顺序排列，未知键追加在末尾
                # (cp-csp-benchmark-hw 含 cp_enclave_time/csp_roundtrip 等额外列)
                all_keys = []
                for item in results:
                    if isinstance(item, dict):
                        for k in item:
                            if k not in all_keys:
                                all_keys.append(k)
                preferred = ["operation", "samples", "mean_ms", "p50_ms", "p95_ms",
                             "min_ms", "max_ms", "cp_enclave_time_ms",
                             "csp_roundtrip_ms", "csp_roundtrip_time_ms",
                             "cp_time_ms", "correct"]
                headers = [k for k in preferred if k in all_keys] + \
                          [k for k in all_keys if k not in preferred]
                rows = []
                for item in results:
                    row = []
                    for h in headers:
                        if h == "correct":
                            row.append(status_badge("passed" if item.get("correct") else "failed"))
                        elif h.endswith("_ms"):
                            row.append(fmt_ms(item.get(h)))
                        else:
                            v = item.get(h, "—")
                            row.append(str(v) if v is not None else "—")
                    rows.append(row)
                L.append(md_table(headers, rows))
            else:
                L.append("```json")
                L.append(json.dumps(data, ensure_ascii=False, indent=2))
                L.append("```\n")
    L.append("")

    # 构建产物
    L.append("## 构建产物\n")
    if r["build_manifests"]:
        rows = []
        for mf in r["build_manifests"]:
            rows.append([
                mf.get("_dir", "—"),
                mf.get("cmake_preset") or "—",
                mf.get("soci_sgx_mode", "—"),
                mf.get("compiler", "—"),
                mf.get("version", "—"),
            ])
        L.append(md_table(["构建目录", "preset", "模式", "编译器", "版本"], rows))
    else:
        L.append("_(无 build-manifest.json)_")
    L.append("")

    # dist
    L.append("## HW 部署镜像 (`dist/`)\n")
    dist = r["dist"]
    rows = [[f["name"], fmt_bytes(f["size"])] for f in dist["files"]]
    L.append(md_table(["文件", "大小"], rows))
    L.append("")
    rows = [
        ["镜像 ID", dist["image_id"]],
        ["归档 SHA256", dist["archive_sha256"]],
        ["SHA256 校验", status_badge("ok" if dist["sha256_verify"] == "ok"
                                     else ("failed" if dist["sha256_verify"] == "failed" else "skipped"))],
        ["已加载镜像", dist["docker_images_soci"]],
    ]
    L.append(md_table(["项", "值"], rows))
    L.append("")

    # 说明
    L.append("## 说明与限制\n")
    L.append("- OFF 模式不涉及 SGX，密钥文件仅供测试，不保密。")
    L.append("- SIM 模式使用真实 EDL/ECALL/Enclave，但不需要 SGX 硬件；其数据不代表 HW 性能。")
    L.append("- HW 模式需要 SGX CPU/BIOS/驱动与 `/dev/sgx_enclave`；本报告未含远程证明。")
    L.append("- SMUL/SCMP/SABS/SDIV 等参考协议为 `experimental_reference_only`，安全模型不满足生产要求，默认关闭。")
    L.append("- 3072-bit Paillier 模数对应约 128-bit 经典安全强度；低于 3072-bit 的密钥生成会被拒绝。")
    L.append("- 详见 `README.md`、`docs/SECURITY.md`、`docs/BENCHMARK.md`、`docs/DEPLOYMENT.md`。\n")

    # 附录
    L.append("## 附录: 步骤日志\n")
    L.append("各步骤完整输出位于 `results/report-artifacts/<mode>-<step>.log`，状态码见 `.status` 文件；"
             "环境探测见 `env.txt`。\n")
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser(description="渲染 SOCI SGX SDK 测试报告")
    ap.add_argument("--project", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--artifacts", required=True)
    args = ap.parse_args()

    report = build_report(args.project, args.out, args.artifacts)
    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    md_path = out_dir / "test-report.md"
    json_path = out_dir / "test-report.json"

    md_path.write_text(render_md(report), encoding="utf-8")
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"  Markdown: {md_path}")
    print(f"  JSON:     {json_path}")
    print(f"  结论:     {report['verdict']}")


if __name__ == "__main__":
    main()
