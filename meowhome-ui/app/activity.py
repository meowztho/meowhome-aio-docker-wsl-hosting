"""Read-only, bounded projection of the canonical audit JSONL log."""
import json
from pathlib import Path
from typing import Any
MAX_TAIL_BYTES=512*1024
MAX_ROWS=100
DISPLAY_FIELDS=("ts","actor","action","target","success")
def recent_activity(path: Path, *, limit: int=50)->list[dict[str,Any]]:
    count=max(1,min(int(limit),MAX_ROWS))
    try:
        with path.open("rb") as fh:
            fh.seek(0,2)
            start=max(0,fh.tell()-MAX_TAIL_BYTES)
            fh.seek(start)
            if start: fh.readline()
            records=fh.read().splitlines()
    except OSError:
        return []
    events=[]
    for raw in reversed(records):
        if len(events)>=count: break
        try: row=json.loads(raw)
        except (UnicodeDecodeError,ValueError): continue
        if not isinstance(row,dict) or not isinstance(row.get("success"),bool): continue
        event={k:str(row.get(k,""))[:256] for k in DISPLAY_FIELDS if k!="success"}
        event["success"]=row["success"]
        events.append(event)
    return events
