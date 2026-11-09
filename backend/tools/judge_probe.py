"""Score a few saved reviews with the DeepEval judge, to check the judge setup before a full run.
Run from backend/:  ..\\aienv\\Scripts\\python.exe -m tools.judge_probe RUN_ID G002 G006 G012
"""
import asyncio
import json
import sys

from prism import llm
from prism.eval import harness, judge


async def main(run_id: str, ids: list[str]) -> None:
    golden = {g["id"]: g for g in harness.load_golden()}
    rows = {r["id"]: r for r in harness.load_rows(run_id, "system_vB")}
    gw = llm.Gateway(run_id=f"{run_id}_judgeprobe")
    for gid in ids:
        s = await judge.score(gw, rows[gid], golden[gid], 0.85)
        print(gid, golden[gid]["category"], s.get("score"), (s.get("reason") or s.get("error") or "")[:240])
    print("judge requests:", gw.calls, "ledger:", llm.ledger().get(llm._day()))


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1], sys.argv[2:]))
