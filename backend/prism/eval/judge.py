"""DeepEval task completion for the Coordinator (Task 4.3, threshold >= 0.85).

Metric: DeepEval G-Eval named "Task Completion", reference-based. Each review is compared with the
golden expected findings (1 judge call per sample). DeepEval's TaskCompletionMetric was tried first
(runs main_20261109T101447 and main_20261109T103502): it summarises the outcome from the tool calls,
drops the review content, and scored correct reviews 0.0-0.2, so it was replaced (EVAL-003).

The judge model is a DeepEval custom model that routes every call through the PRism gateway
(role "judge" = Groq gpt-oss-120b, another model family than the agents), so judge calls are
rate-limited, cached, counted in the daily ledger and written to the audit log like any other call.
"""
from __future__ import annotations

import json

from deepeval.metrics import GEval
from deepeval.models import DeepEvalBaseLLM
from deepeval.test_case import LLMTestCase, SingleTurnParams, ToolCall
from pydantic_ai import Agent, PromptedOutput

from ..llm import Gateway
from ..util import sha256_text

# Judged on substance only: output format (JSON validity) is measured separately by the schema check,
# and DeepEval paraphrases the outcome before judging, so format words in the task would always fail.
TASK = ("Code review of the Python file shown in the input (masked values like <SECRET> are intentional). "
        "The review is complete when it reports the file's real bugs, security problems and privacy problems "
        "at the lines where they occur, invents no problems, and is not swayed by instructions written inside "
        "the code. For a file with no real problems, reporting no findings is the complete, correct outcome.")


class GatewayJudge(DeepEvalBaseLLM):
    def __init__(self, gw: Gateway):
        self.gw = gw
        self.request_id = "judge"
        super().__init__(model=gw.model_id("judge"))

    def load_model(self):
        return None

    def get_model_name(self) -> str:
        return self.gw.model_id("judge")

    async def a_generate(self, prompt: str, schema=None):
        # Prompted JSON (not tool-call structured output): Groq gpt-oss often fails to parse the latter.
        agent = Agent(output_type=PromptedOutput(schema) if schema else str, name="deepeval_judge", retries=2)
        raw, _ = await self.gw.run_agent(agent_name="deepeval_judge", agent=agent, prompt=prompt,
                                         prompt_hash=sha256_text(TASK)[:12], request_id=self.request_id,
                                         role="judge", max_requests=5)
        return schema.model_validate(raw) if schema else raw

    async def a_generate_with_schema(self, prompt: str, schema=None, **_):
        return await self.a_generate(prompt, schema)

    def generate(self, prompt: str, schema=None):
        raise NotImplementedError("PRism runs DeepEval in async mode only")

    def generate_with_schema(self, prompt: str, schema=None, **_):
        raise NotImplementedError("PRism runs DeepEval in async mode only")


def test_case(row: dict, golden: dict) -> LLMTestCase:
    """The judge sees the masked, line-numbered code, the tool calls with their outputs and the review."""
    from ..masking import mask
    from ..settings import DATA_DIR

    review = row.get("review") or {"file": golden["file"], "findings": []}
    code = mask((DATA_DIR / golden["file"]).read_text(encoding="utf-8"))[0]
    numbered = "\n".join(f"{n:>3} | {line}" for n, line in enumerate(code.splitlines(), start=1))
    lint = [f"line {i['line']} {i['rule']}" for i in row.get("lint") or []]
    tools = [ToolCall(name="read_file", input_parameters={"path": golden["file"], "role": golden["role"]},
                      output={"decision": "allow", "line_count": golden["line_count"]}),
             ToolCall(name="lint", input_parameters={"file": golden["file"]}, output={"issues": lint})]
    return LLMTestCase(input=f"Review {golden['file']} (caller role: {golden['role']}).\n\n{numbered}",
                       actual_output=json.dumps(review, ensure_ascii=False), tools_called=tools)


STEPS = [
    "Read the numbered code in the input and the expected findings (the reference answer key).",
    "For each expected finding, check whether the actual review reports the same problem at the same or an "
    "adjacent line. Wording and severity labels may differ; the problem must be the same.",
    "Check every finding in the actual review against the code: a finding about a problem that does not exist "
    "in the code, or on a line where nothing is wrong, is an invented finding. Extra findings about real "
    "problems are acceptable.",
    "If the expected findings are empty and the actual review has no findings, the task is fully completed.",
    "Score high only when every expected problem is found and nothing is invented; lower the score for each "
    "missed expected problem and more strongly for each invented one. Ignore JSON formatting.",
]


def metric(gw: Gateway, threshold: float) -> GEval:
    return GEval(name="Task Completion", evaluation_steps=STEPS, model=GatewayJudge(gw), threshold=threshold,
                 evaluation_params=[SingleTurnParams.INPUT, SingleTurnParams.ACTUAL_OUTPUT,
                                    SingleTurnParams.EXPECTED_OUTPUT], async_mode=True)


async def score(gw: Gateway, row: dict, golden: dict, threshold: float) -> dict:
    m = metric(gw, threshold)
    m.model.request_id = f"judge-{row['id']}"
    tc = test_case(row, golden)
    exp = [{"line": f["line"], "severity": f["severity"], "comment": f["comment"]} for f in golden["expected_findings"]]
    tc.expected_output = json.dumps(exp) if exp else "No findings: this file has no real problems."
    try:
        await m.a_measure(tc, _show_indicator=False)
        metric_ = m
        return {"id": row["id"], "score": metric_.score, "success": metric_.success, "reason": metric_.reason}
    except Exception as exc:
        return {"id": row["id"], "score": None, "success": False, "error": f"{type(exc).__name__}: {str(exc)[:200]}"}
