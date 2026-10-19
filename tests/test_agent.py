#!/usr/bin/env python3
"""Offline tests for the LLM agent layer using a scripted model and stubbed audit stages."""

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

MARKETPLACE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, MARKETPLACE_DIR)

from agent.core import AuditAgent  # noqa: E402
from agent.providers import ChatModel, ModelError  # noqa: E402
from agent.tools import Toolbox, html_to_text  # noqa: E402

STAGE_FINDINGS = {
    "technical": {"findings": [{
        "title": "AI crawlers blocked in robots.txt",
        "severity": "high",
        "confidence": 0.95,
        "evidence": "GPTBot is disallowed.",
        "affected_pages": ["https://shop.example/"],
        "suggested_action": {"summary": "Allow AI crawlers", "priority": "high", "how_to_fix": "Edit robots.txt"},
    }], "crawl_scope": {"crawled_urls": ["https://shop.example/", "https://shop.example/about"]}},
    "trust": {"findings": [{
        "title": "No author or organisation transparency",
        "severity": "medium",
        "confidence": 0.8,
        "evidence": "No about or author information found.",
        "affected_pages": ["https://shop.example/"],
        "suggested_action": {"summary": "Add an about page", "priority": "medium", "how_to_fix": "Publish team info"},
    }]},
    "engagement": {"findings": [{
        "title": "Missing primary call to action",
        "severity": "medium",
        "confidence": 0.85,
        "evidence": "No visible CTA above the fold.",
        "affected_pages": ["https://shop.example/"],
        "suggested_action": {"summary": "Add a CTA", "priority": "medium", "how_to_fix": "Add a buy button"},
    }]},
}


class StubToolbox(Toolbox):
    """Writes fixture findings instead of running network-bound skill scripts."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.commands = []

    def run_stage(self, cmd, timeout):
        self.commands.append([str(c) for c in cmd])
        script = Path(str(cmd[0])).name
        name = {"check_technical.py": "technical", "check_trust.py": "trust", "check_engagement.py": "engagement"}[script]
        out = Path(str(cmd[cmd.index("--output") + 1]))
        out.write_text(json.dumps(STAGE_FINDINGS[name]), encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, "", ""), None

    def fetch_html(self, url):
        return "<html><title>Shop</title><script>x()</script><body><h1>Shop Example</h1><p>Handmade tea from Delhi.</p></body></html>"


def call(name, args, call_id=None):
    return {"id": call_id or name, "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}


class ScriptedModel:
    provider_name = "scripted"
    model = "scripted-1"

    def __init__(self, turns, probe_answer="I am not sure what Shop Example sells."):
        self.turns = list(turns)
        self.probe_answer = probe_answer
        self.requests = []

    def chat(self, messages, tools=None, temperature=0.2):
        self.requests.append({"messages": [dict(m) for m in messages], "tools": tools})
        if tools is None:  # brand probe call
            return {"role": "assistant", "content": self.probe_answer}
        return self.turns.pop(0) if self.turns else {"role": "assistant", "content": "done"}


def full_run_turns():
    return [
        {"role": "assistant", "content": "Starting with the crawl.", "tool_calls": [call("run_technical_audit", {"max_pages": 2})]},
        {"role": "assistant", "content": None, "tool_calls": [
            call("run_trust_audit", {"pages": ["https://shop.example/about"]}),
            call("run_engagement_audit", {}),
        ]},
        {"role": "assistant", "content": None, "tool_calls": [call("fetch_page_text", {"url": "/"})]},
        {"role": "assistant", "content": None, "tool_calls": [call("ask_ai_about_brand", {"questions": ["What does Shop Example sell?"]})]},
        {"role": "assistant", "content": None, "tool_calls": [call("finish_audit", {
            "summary": "AI crawlers are blocked, so assistants cannot learn about the shop.",
            "top_fixes": [{"title": "Unblock AI crawlers", "why": "GPTBot is disallowed", "how": "Edit robots.txt", "finding_ids": ["F-001"]}],
            "ai_perception": [{"question": "What does Shop Example sell?", "ai_answer": "Not sure", "site_fact": "Handmade tea", "verdict": "unknown"}],
        })]},
    ]


class TestAgentLoop(unittest.TestCase):
    def run_agent(self, model, **kwargs):
        events = []
        agent = AuditAgent(model, on_event=events.append, **kwargs)
        toolbox = StubToolbox("shop.example", model)
        try:
            return agent.run("shop.example", toolbox=toolbox), events, toolbox
        finally:
            toolbox.close()

    def test_full_run_produces_report_with_agent_section(self):
        report, events, toolbox = self.run_agent(ScriptedModel(full_run_turns()))
        self.assertEqual(report["agent"]["stop_reason"], "finished")
        self.assertEqual(report["summary"]["total_findings"], 3)
        self.assertEqual(report["agent"]["top_fixes"][0]["title"], "Unblock AI crawlers")
        self.assertEqual(report["agent"]["probe_answers"][0]["question"], "What does Shop Example sell?")
        self.assertFalse(report["execution"].get("missing_categories"))
        self.assertIn("tool_call", {e["type"] for e in events})
        self.assertEqual(events[-1]["type"], "done")

    def test_trust_audit_receives_technical_context_and_pages(self):
        _, _, toolbox = self.run_agent(ScriptedModel(full_run_turns()))
        trust_cmd = next(c for c in toolbox.commands if c[0].endswith("check_trust.py"))
        self.assertIn("--technical", trust_cmd)
        self.assertIn("https://shop.example/about", trust_cmd[trust_cmd.index("--pages") + 1])

    def test_finish_refused_until_all_stages_ran(self):
        turns = [
            {"role": "assistant", "tool_calls": [call("finish_audit", {"summary": "x", "top_fixes": []})]},
        ] + full_run_turns()
        model = ScriptedModel(turns)
        report, _, _ = self.run_agent(model)
        first_tool_reply = next(m for m in model.requests[1]["messages"] if m["role"] == "tool")
        self.assertIn("Run these audits before finishing", first_tool_reply["content"])
        self.assertEqual(report["agent"]["stop_reason"], "finished")

    def test_off_site_urls_are_refused(self):
        turns = [{"role": "assistant", "tool_calls": [call("fetch_page_text", {"url": "http://169.254.169.254/latest"})]}]
        model = ScriptedModel(turns)
        self.run_agent(model, max_steps=2)
        tool_reply = next(m for m in model.requests[1]["messages"] if m["role"] == "tool")
        self.assertIn("Only pages on shop.example", tool_reply["content"])

    def test_step_limit_still_returns_partial_report(self):
        turns = [{"role": "assistant", "tool_calls": [call("run_technical_audit", {})]}] * 3
        report, _, _ = self.run_agent(ScriptedModel(turns), max_steps=2)
        self.assertEqual(report["agent"]["stop_reason"], "step_limit")
        self.assertTrue(report["execution"]["partial"])
        self.assertEqual(sorted(report["execution"]["missing_categories"]), ["engagement", "trust"])

    def test_stage_rerun_is_capped(self):
        turns = [{"role": "assistant", "tool_calls": [call("run_technical_audit", {})]}] * 3
        model = ScriptedModel(turns)
        _, _, toolbox = self.run_agent(model, max_steps=3)
        self.assertEqual(len(toolbox.commands), 2)

    def test_prose_reply_is_nudged_then_stops(self):
        turns = [{"role": "assistant", "content": "Looks fine."}, {"role": "assistant", "content": "Still fine."}]
        report, _, _ = self.run_agent(ScriptedModel(turns))
        self.assertEqual(report["agent"]["stop_reason"], "model_stopped")

    def test_bad_json_arguments_are_reported_to_model(self):
        bad = {"id": "1", "type": "function", "function": {"name": "run_trust_audit", "arguments": "{oops"}}
        model = ScriptedModel([{"role": "assistant", "tool_calls": [bad]}])
        self.run_agent(model, max_steps=2)
        tool_reply = next(m for m in model.requests[1]["messages"] if m["role"] == "tool")
        self.assertIn("not valid JSON", tool_reply["content"])


class TestHelpers(unittest.TestCase):
    def test_html_to_text_skips_scripts(self):
        title, text = html_to_text("<title>T</title><style>a{}</style><p>Hello <b>world</b></p><script>bad()</script>")
        self.assertEqual(title, "T")
        self.assertEqual(text, "Hello world")

    def test_missing_key_explains_where_to_get_one(self):
        os.environ.pop("GROQ_API_KEY", None)
        with self.assertRaises(ModelError) as ctx:
            ChatModel("groq")
        self.assertIn("GROQ_API_KEY", str(ctx.exception))

    def test_ollama_needs_no_key(self):
        self.assertEqual(ChatModel("ollama").model, "llama3.1")


if __name__ == "__main__":
    unittest.main()
