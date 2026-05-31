#!/usr/bin/env python3
"""
通用上下文渲染器
提供统一的上下文格式化功能，确保所有Agent看到的“世界”是一致的
"""

from typing import Any


def render_causal_graph(context: dict[str, Any], mode: str = "full") -> str:
    """
    统一的因果图渲染逻辑。

    Args:
        context: 因果图上下文数据
        mode: 渲染模式
            - "full": 完整图谱摘要(用于Planner/Reflector)
            - "relevant": 过滤后的相关上下文(用于Executor)

    Returns:
        格式化的因果图文本
    """
    if not context:
        return "因果图暂不可用。"

    if mode == "relevant":
        return _render_relevant_causal_context(context)
    return _render_full_causal_graph(context)


def _render_full_causal_graph(context: dict[str, Any]) -> str:
    """渲染完整的因果图谱摘要。"""
    lines = ["### 🗺️ 系统因果认知图谱 (Causal Knowledge Graph)"]

    # 1. 关键事实
    key_facts = context.get("key_facts", [])
    if key_facts:
        lines.append("\n#### 🔑 核心事实 (Ground Truth)")
        for i, fact in enumerate(key_facts, 1):
            fact_text = fact if isinstance(fact, str) else fact.get("description", str(fact))
            lines.append(f"{i}. {fact_text}")

    # 2. 高置信度假设
    hypotheses = context.get("hypotheses", [])
    if hypotheses:
        lines.append("\n#### 🔬 高置信度假设 (Hypotheses)")
        for h in hypotheses[:5]:  # 限制显示数量
            status = h.get("status", "unknown")
            desc = h.get("description", "N/A")
            conf = h.get("confidence", 0)
            lines.append(f"- [{status}] **{desc}** (置信度: {conf:.2f})")

    # 3. 已确认漏洞
    vulns = context.get("confirmed_vulnerabilities", [])
    if vulns:
        lines.append("\n#### 🚨 已确认漏洞 (Confirmed Vulnerabilities)")
        for v in vulns:
            desc = v.get("description", "N/A")
            cvss = v.get("cvss_score", "N/A")
            lines.append(f"- **{desc}** (CVSS: {cvss})")

    return "\n".join(lines)


def _render_relevant_causal_context(causal_context: dict[str, Any]) -> str:
    """
    将get_relevant_causal_context返回的结构化数据格式化为供Executor使用的文本。
    Executor只需要与当前任务相关的、经过过滤的上下文，而非完整图谱。
    """
    if not causal_context:
        return "## 相关因果链上下文\n暂无与本任务相关的情报。\n"

    lines = ["## 📊 相关因果链上下文 (Relevant Causal Context)"]
    lines.append("＊＊以下是与当前子任务最相关的情报，经过智能过滤，避免信息过载:＊＊\n")

    # 1. 高置信度假设
    hypotheses = causal_context.get("related_hypotheses", [])
    if hypotheses:
        lines.append("### 🔬 高置信度假设 (High-Confidence Hypotheses)")
        for h in hypotheses:
            status = h.get("status", "unknown")
            desc = h.get("description", "N/A")
            conf = h.get("confidence", 0)
            lines.append(f"- [{status}] **{desc}** (置信度: {conf:.2f})")
        lines.append("")

    # 2. 已确认漏洞
    vulns = causal_context.get("confirmed_vulnerabilities", [])
    if vulns:
        lines.append("### 🚨 已确认漏洞 (Confirmed Vulnerabilities)")
        for v in vulns:
            desc = v.get("description", "N/A")
            cvss = v.get("cvss_score", "N/A")
            lines.append(f"- **{desc}** (CVSS: {cvss})")
        lines.append("")

    # 3. 热门攻击路径
    paths = causal_context.get("top_attack_paths", [])
    if paths:
        lines.append("### 🗺️ 热门攻击路径 (Top Attack Paths)")
        for i, p in enumerate(paths, 1):
            path_desc = p.get("path_description", "N/A")
            score = p.get("score", 0)
            lines.append(f"{i}. {path_desc} (score: {score:.2f})")
        lines.append("")

    # 4. 失败模式(简化显示)
    failure_patterns = causal_context.get("failure_patterns", {})
    if failure_patterns and failure_patterns.get("repeated_failures"):
        lines.append("### ⚠️ 已知失败模式 (Failure Patterns to Avoid)")
        for pattern in failure_patterns.get("repeated_failures", [])[:3]:  # 只显示前3个
            action_type = pattern.get("action_type", "N/A")
            reason = pattern.get("reason", "N/A")
            count = pattern.get("count", 0)
            lines.append(f"- {action_type}: {reason} (失败{count}次)")
        lines.append("")

    # 5. 已确认但未利用的漏洞提示
    if failure_patterns and failure_patterns.get("unexploited_vulnerabilities"):
        unexp_vulns = failure_patterns.get("unexploited_vulnerabilities", [])
        if unexp_vulns:
            lines.append("### 💤 待利用漏洞 (Confirmed but Unexploited Vulnerabilities)")
            lines.append("**以下漏洞已被确认存在,但尚未有对应的 Exploit 节点。请优先评估并规划利用路径!**")
            for uv in unexp_vulns[:5]:  # 最多展示前5个
                desc = uv.get("description", "N/A")
                age = int(uv.get("age_seconds", 0))
                vuln_id = uv.get("id", "unknown")
                lines.append(f"- [{vuln_id}] {desc} (已停滞 {age}s)")
            lines.append("")

    return "\n".join(lines)


def render_failure_patterns(patterns: dict[str, Any]) -> str:
    """
    统一的失败模式渲染（含竞争假设消解）。

    Args:
        patterns: 失败模式数据字典，可能包含：
            - contradiction_clusters: 矛盾证据簇
            - stalled_hypotheses: 停滞假设
            - competing_hypotheses: 竞争假设（需消歧）

    Returns:
        格式化的失败模式文本
    """
    if not patterns:
        return "无已知的失败模式。"

    # 兼容旧版调用：如果传入的是字符串，直接返回
    if isinstance(patterns, str):
        return f"### ⚠️ 历史失败模式\n{patterns}"

    lines = ["### ⚠️ 因果图问题检测 (Causal Graph Issues)"]

    # 1. 矛盾簇
    contradiction_clusters = patterns.get("contradiction_clusters", [])
    if contradiction_clusters:
        lines.append("\n#### 🔴 矛盾证据簇 (Contradiction Clusters)")
        for cluster in contradiction_clusters:
            hypo_id = cluster.get("hypothesis_id", "unknown")
            count = cluster.get("contradicting_evidence_count", 0)
            desc = cluster.get("hypothesis_description", "")[:60]
            lines.append(f"- 假设 `{hypo_id}`: \"{desc}...\" 有 **{count}** 条矛盾证据")

    # 2. 停滞假设
    stalled_hypotheses = patterns.get("stalled_hypotheses", [])
    if stalled_hypotheses:
        lines.append("\n#### 🟡 停滞假设 (Stalled Hypotheses)")
        for hypo in stalled_hypotheses[:5]:  # 限制显示数量
            hypo_id = hypo.get("id", "unknown")
            desc = hypo.get("description", "")[:50]
            age = int(hypo.get("age_seconds", 0))
            reason = hypo.get("reason", "")
            lines.append(f"- `{hypo_id}`: \"{desc}...\" (停滞 {age}s, 原因: {reason})")

    # 3. 竞争假设（溯因推理核心）
    competing_hypotheses = patterns.get("competing_hypotheses", [])
    if competing_hypotheses:
        lines.append("\n#### 🔀 竞争假设 (Competing Hypotheses - Abductive Disambiguation Needed)")
        lines.append("**以下证据支持多个相互竞争的假设，需生成区分性探测任务来确定最佳解释：**")
        for comp in competing_hypotheses:
            evidence_id = comp.get("evidence_id", "unknown")
            evidence_desc = comp.get("evidence_description", "")[:40]
            hypotheses = comp.get("hypotheses", [])
            hypo_list = ", ".join([f"`{h.get('id', '')}`({h.get('edge_label', '')})" for h in hypotheses[:3]])
            lines.append(f"- 证据 `{evidence_id}`: \"{evidence_desc}...\"")
            lines.append(f"  → 竞争假设: {hypo_list}")

    # 如果没有任何问题，显示简洁信息
    if len(lines) == 1:
        return "无已知的失败模式。"

    return "\n".join(lines)


def render_key_facts(key_facts: list[Any]) -> str:
    """
    统一的关键事实渲染。

    Args:
        key_facts: 关键事实列表

    Returns:
        格式化的关键事实文本
    """
    if not key_facts:
        return ""

    lines = ["### 🔑 关键事实 (Key Facts - Ground Truth)"]
    lines.append("＊＊以下是已确认的、不容置疑的核心事实。你必须将这些信息作为所有决策的基础:＊＊")
    lines.append(
        "＊＊⚠️ 严禁重复执行:如果看到“已完成”、“已测试”、“已扫描”等字样，表示该操作已执行，你不得重复进行相同探测!＊＊\n"
    )

    for i, fact in enumerate(key_facts, 1):
        fact_text = fact if isinstance(fact, str) else fact.get("description", str(fact))
        lines.append(f"{i}. ✅ {fact_text}")

    return "\n".join(lines) + "\n"


def _dep_task_id(dep: dict[str, Any]) -> str:
    return dep.get("task_id") or dep.get("id") or "unknown"


def _dep_description(dep: dict[str, Any]) -> str:
    return dep.get("description") or dep.get("summary") or "N/A"


def _dep_status(dep: dict[str, Any]) -> str:
    return dep.get("status", "unknown")


def _get_key_findings(dep: dict[str, Any]) -> list[str] | None:
    key_findings = dep.get("key_findings")
    if not key_findings and isinstance(dep.get("summary"), str) and dep.get("summary").strip():
        key_findings = [dep["summary"]]
    return key_findings


def _get_failure_reason(dep: dict[str, Any]) -> str | None:
    failure_reason = dep.get("failure_reason")
    if not failure_reason:
        status_val = str(_dep_status(dep)).lower()
        if status_val.startswith("failed") or status_val == "failed":
            failure_reason = dep.get("reflection") or dep.get("summary")
    return failure_reason


def _get_nodes_produced(dep: dict[str, Any]) -> list[str] | None:
    nodes_produced = dep.get("nodes_produced")
    if not nodes_produced and dep.get("artifacts"):
        try:
            nodes_produced = []
            for a in dep.get("artifacts", [])[:10]:
                if isinstance(a, dict):
                    nodes_produced.append(a.get("id") or a.get("name") or a.get("type") or str(a))
                else:
                    nodes_produced.append(str(a))
        except Exception:
            nodes_produced = None
    return nodes_produced


def render_dependencies_summary(deps: list[dict[str, Any]]) -> str:
    """
    格式化依赖任务摘要。

    Args:
        deps: 依赖任务列表

    Returns:
        格式化的依赖任务摘要文本
    """
    if not deps:
        return "无依赖任务。这是一个独立的初始任务。"

    lines: list[str] = []
    for dep in deps:
        task_id = _dep_task_id(dep)
        description = _dep_description(dep)
        status = _dep_status(dep)

        lines.append(f"### 任务 {task_id}")
        lines.append(f"- **目标**: {description}")
        lines.append(f"- **状态**: {status}")

        key_findings = _get_key_findings(dep)
        if key_findings:
            lines.append("- **关键发现**:")
            for finding in key_findings:
                lines.append(f"  - {finding}")

        failure_reason = _get_failure_reason(dep)
        if failure_reason:
            lines.append(f"- ⚠️ **失败原因**: {failure_reason}")

        exec_summary = dep.get("execution_summary")
        if exec_summary:
            lines.append("- **执行摘要**:")
            lines.append(exec_summary)

        nodes_produced = _get_nodes_produced(dep)
        if nodes_produced:
            lines.append(f"- **节点产出**: {', '.join(nodes_produced)}")

        lines.append("")

    if not lines:
        return "无依赖任务摘要。"

    return "\n".join(lines)


def render_domain_knowledge(role: str) -> str:
    """
    根据角色动态加载领域知识，从模板文件中加载。

    Args:
        role: 角色名称 ("planner", "executor", "reflector")

    Returns:
        领域知识文本
    """
    import os

    from jinja2 import Environment, FileSystemLoader

    # 获取组件模板目录
    template_dir = os.path.join(os.path.dirname(__file__), "templates")

    # 创建Jinja2环境
    env = Environment(loader=FileSystemLoader(template_dir))

    # 加载领域知识模板
    template = env.get_template("common/domain_knowledge.jinja2")

    # 渲染模板(未来可以根据role传入不同参数)
    return template.render()
