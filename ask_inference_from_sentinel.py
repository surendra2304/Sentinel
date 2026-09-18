import asyncio
import os
import sys
import time
import httpx
from dotenv import load_dotenv

sys.stdout.reconfigure(encoding="utf-8")
load_dotenv()

questions = [
    "What zero-trust verification criteria should govern inter-agent RPC calls across local and cloud environments?",
    "How can HMAC audit chains be optimized for zero-overhead validation across distributed microservices?",
    "Evaluate anomalous token consumption patterns as an indicator of prompt injection or model evasion attacks.",
    "What rate limiting and IP reputation defense mechanisms best mitigate distributed credential stuffing attacks?",
    "How should security posture scoring aggregate disparate telemetry findings across network, API, and host domains?"
]

async def main():
    print("=" * 80)
    print("AGENT [6/9]: SENTINEL -> INFERENCE GATEWAY (5 QUESTIONS)")
    print("Client: Sentinel Ecosystem Integration Client")
    print("=" * 80)
    
    inf_url = os.getenv("INFERENCE_URL", "https://inference-r1sn.onrender.com").rstrip("/")
    api_key = os.getenv("INFERENCE_API_KEY", "inference_api")
    print(f"Target URL: {inf_url}")
    print(f"API Key:    {api_key[:4]}...")
    
    headers = {
        "X-FRIDAY-API-Key": api_key,
        "X-Originating-Service": "sentinel",
        "Content-Type": "application/json"
    }
    
    results = []
    async with httpx.AsyncClient(timeout=90.0) as client:
        for i, q in enumerate(questions, 1):
            t0 = time.perf_counter()
            payload = {
                "question": q,
                "caller_id": "sentinel_security_core",
                "context_data": {"agent": "sentinel", "domain": "cybersecurity"}
            }
            try:
                resp = await client.post(f"{inf_url}/v1/friday/ask", json=payload, headers=headers)
                lat = (time.perf_counter() - t0) * 1000
                if resp.status_code == 200:
                    data = resp.json()
                    run_id = data.get("run_id", "N/A")
                    ans_snip = data.get("answer", "")[:120].replace("\n", " ")
                    print(f"[SENTINEL Q{i}/5] HTTP 200 | {lat:>7.1f}ms | Run: {run_id} | Ans: {ans_snip}...")
                    results.append({"q_num": i, "status": 200, "latency_ms": round(lat, 1), "run_id": run_id, "answer": ans_snip})
                else:
                    print(f"[SENTINEL Q{i}/5] HTTP {resp.status_code} | {lat:>7.1f}ms")
                    results.append({"q_num": i, "status": resp.status_code, "latency_ms": round(lat, 1)})
            except Exception as e:
                lat = (time.perf_counter() - t0) * 1000
                print(f"[SENTINEL Q{i}/5] ERROR | {lat:>7.1f}ms | {e}")
                results.append({"q_num": i, "status": "ERROR", "latency_ms": round(lat, 1), "error": str(e)})
                
    print("-" * 80)
    lats = [r["latency_ms"] for r in results if r["status"] == 200]
    if lats:
        print(f"SENTINEL Batch Complete: Avg Latency = {sum(lats)/len(lats):.1f}ms (Min: {min(lats):.1f}ms, Max: {max(lats):.1f}ms)")
    print("=" * 80 + "\n")

if __name__ == "__main__":
    asyncio.run(main())
