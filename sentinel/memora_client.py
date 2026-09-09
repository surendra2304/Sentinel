"""
Universal Memora Client for Sentinel Cybersecurity & Gatekeeper
"""
import os
import sys
from pathlib import Path

try:
    MEMORA_ROOT = Path("d:/FRIDAY Universe/Memora")
    if str(MEMORA_ROOT) not in sys.path:
        sys.path.insert(0, str(MEMORA_ROOT))
    from sdk.memora_client import MemoraClient, memora_client
except Exception:
    import sqlite3
    import uuid
    import time
    from typing import Optional, Dict, Any, List

    class MemoraClient:
        def __init__(self):
            self.local_db_path = "d:/FRIDAY Universe/Memora/data/memora.db"

        def record_security_decision(self, action_type: str, approval_status: str, fingerprint: str, details: str):
            if not os.path.exists(self.local_db_path):
                return
            try:
                with sqlite3.connect(self.local_db_path, timeout=5.0) as conn:
                    c = conn.cursor()
                    c.execute("SELECT id FROM agents WHERE name = 'sentinel'")
                    row = c.fetchone()
                    aid = row[0] if row else str(uuid.uuid4())
                    c.execute("SELECT id FROM namespaces WHERE agent_id = ?", (aid,))
                    row_ns = c.fetchone()
                    nid = row_ns[0] if row_ns else str(uuid.uuid4())
                    now_iso = time.strftime("%Y-%m-%d %H:%M:%S")
                    content = f"Sentinel Security Decision: {action_type} -> Status: {approval_status} (Fingerprint: {fingerprint}). {details}"
                    c.execute("""
                        INSERT INTO memory_records (id, namespace_id, owner_id, memory_type, content_text, source, confidence, importance, lifecycle_state, tenant_id, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (str(uuid.uuid4()), nid, aid, "semantic", content, "agent:sentinel", 1.0, 0.9, "active", "default", now_iso))
                    conn.commit()
            except Exception:
                pass

        def recall_memories(self, agent_name: str, query: str, limit: int = 5):
            return []

    memora_client = MemoraClient()

__all__ = ["MemoraClient", "memora_client"]
