import xml.etree.ElementTree as ET
from datetime import datetime
from zoneinfo import ZoneInfo
import csv
from pathlib import Path

# INPUT: set to your file that contains <Event> entries under one root
INPUT_FILE = "securityEvt_formatted.xml"  # change if needed

# Time window and timezone from Question 4 (Eastern)
LOCAL_TZ = ZoneInfo("America/New_York")
WINDOW_START_HOUR = 9   # inclusive
WINDOW_END_HOUR   = 18  # exclusive

# Event IDs of interest
SYSTEM_EVENTS = {
    "12":  "SystemStart (Kernel-General)",
    "13":  "SystemShutdown (Kernel-General)",
    "6005":"EventLog Started (Boot)",
    "6006":"EventLog Stopped (Shutdown)",
    "6008":"Unexpected Shutdown",
}
SECURITY_EVENTS = {
    "4624":"Logon Success",
    "4625":"Logon Failure",
    "4634":"Logoff",
    "4647":"User Initiated Logoff",
    "4672":"Special Privileges Assigned",
    "4800":"Workstation Locked",
    "4801":"Workstation Unlocked",
}
ALL_EVENTS = {**SYSTEM_EVENTS, **SECURITY_EVENTS}

def try_iso_to_dt_utc(iso_str: str):
    # Handles "2025-08-21T12:34:56.789Z" or with offset
    if not iso_str:
        return None
    s = iso_str.strip()
    # Normalize trailing Z to +00:00
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(s)
    except Exception:
        return None

def in_window_local(dt_local: datetime) -> bool:
    h = dt_local.hour
    return WINDOW_START_HOUR <= h < WINDOW_END_HOUR

def get_text(elem, path):
    x = elem.find(path)
    return x.text if x is not None else None

def get_attr(elem, path, attr):
    x = elem.find(path)
    return x.get(attr) if x is not None else None

def extract_username(event_elem):
    ed = event_elem.find("EventData")
    if ed is None:
        return None
    user = None
    for d in ed.findall("Data"):
        name = d.get("Name")
        if name in ("TargetUserName", "SubjectUserName"):
            if d.text:
                user = d.text
                break
    return user

def iter_relevant_events(root):
    for ev in root.findall(".//Event"):
        system = ev.find("System")
        if system is None:
            continue
        eid = get_text(system, "EventID")
        if eid not in ALL_EVENTS:
            continue
        system_time_utc = get_attr(system, "TimeCreated", "SystemTime")
        dt_utc = try_iso_to_dt_utc(system_time_utc)
        if dt_utc is None or dt_utc.tzinfo is None:
            # assume UTC if missing tz
            dt_utc = datetime.fromisoformat(system_time_utc.replace("Z","+00:00"))
        dt_local = dt_utc.astimezone(LOCAL_TZ)
        if not in_window_local(dt_local):
            continue

        provider = get_attr(system, "Provider", "Name")
        computer = get_text(system, "Computer")
        label = ALL_EVENTS[eid]
        user = extract_username(ev) if eid in SECURITY_EVENTS else None

        yield {
            "source": "security" if eid in SECURITY_EVENTS else "system",
            "event_id": eid,
            "label": "Logoff" if eid == "4634" else label,
            "provider": provider or "-",
            "computer": computer or "-",
            "utc_time": dt_utc.isoformat(timespec="seconds"),
            "local_time": dt_local.isoformat(sep=" ", timespec="seconds"),
            "user": user or "-",
        }

def main():
    # If your XML is a raw concatenation of <Event> elements, first wrap it with a single root.
    # Otherwise, ElementTree will raise a parse error. Ensure the file has one root containing all events.
    tree = ET.parse(INPUT_FILE)
    root = tree.getroot()

    rows = list(iter_relevant_events(root))
    rows.sort(key=lambda r: r["local_time"])

    # Print human-readable lines
    for r in rows:
        print(f'{r["local_time"]} [{r["source"]}] EventID={r["event_id"]} '
              f'{r["label"]} | Provider={r["provider"]} | Computer={r["computer"]} | User={r["user"]}')

    # Also write CSV
    out_csv = Path(INPUT_FILE).with_suffix(".traces_0900_1800_EST.csv")
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["source","event_id","label","local_time","utc_time","provider","computer","user"])
        for r in rows:
            w.writerow([r["source"], r["event_id"], r["label"], r["local_time"], r["utc_time"],
                        r["provider"], r["computer"], r["user"]])
    print(f"\nSaved: {out_csv}")

if __name__ == "__main__":
    main()
