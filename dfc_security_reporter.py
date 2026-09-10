#!/usr/bin/env python3
"""
dfc_security_reporter.py — DFC Security Event Reporter

Generates a comprehensive HTML report with attack campaigns, detector analysis,
trends, and statistics for the Out of the Path security solution.

Usage:
    python dfc_security_reporter.py
    python dfc_security_reporter.py "Inputs/Forensics Input/attacks.csv" --detector-type arbor
    python dfc_security_reporter.py --input-dir "Inputs/Forensics Input" --detector-type arbor
    python dfc_security_reporter.py --mode html-only --report-csv Reports/existing_report.csv
"""

import argparse
import configparser
import csv
import io
import json
import math
import re
import sys
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional, Union

import numpy as np
import pandas as pd

# ══════════════════════════════════════════════════════════════════
#  Configuration
# ══════════════════════════════════════════════════════════════════

RISK_ORDER = {"Low": 1, "Medium": 2, "High": 3}
RISK_INV = {v: k for k, v in RISK_ORDER.items()}

_BPS_UNIT: str = "auto"
_PPS_UNIT: str = "auto"

SCRIPT_DIR = Path(__file__).resolve().parent
CONFIG_PATH = SCRIPT_DIR / "dfc_security_reporter.ini"

DETECTOR_TYPES = {
    "1": ("kentik", "Kentik"),
    "2": ("arbor", "Arbor"),
    "3": ("defensepro", "DefensePro"),
}

COL_ALIASES = {
    "Start Time": ["Start Time", "Start", "Time Start"],
    "End Time": ["End Time", "End", "Time End"],
    "Device IP Address": ["Device IP Address", "Device IP", "Device"],
    "Destination IP Address": ["Destination IP Address", "Destination IP", "Dst IP", "DstIP"],
    "Destination Port": ["Destination Port", "Dst Port", "DstPort", "Port"],
    "Threat Category": ["Threat Category", "Category"],
    "Attack Name": ["Attack Name", "Attack", "Vector"],
    "Action": ["Action"],
    "Protocol": ["Protocol", "Proto"],
    "Total Packets Dropped": ["Total Packets Dropped", "Packets Dropped"],
    "Total Mbits Dropped": ["Total Mbits Dropped", "Mbits Dropped"],
    "Max pps": ["Max pps", "Peak pps", "pps max"],
    "Max bps": ["Max bps", "Peak bps", "bps max"],
    "Risk": ["Risk"],
    "Policy Name": ["Policy Name", "Policy"],
}


# ══════════════════════════════════════════════════════════════════
#  Helper Functions
# ══════════════════════════════════════════════════════════════════

def resolve_columns(df: pd.DataFrame) -> dict:
    """Resolve column names from various aliases."""
    present = {c.lower().strip(): c for c in df.columns}
    resolved = {}
    
    def find_match(cands: List[str]) -> Optional[str]:
        for c in cands:
            if c in df.columns:
                return c
            low = c.lower().strip()
            if low in present:
                return present[low]
        return None
    
    for canon, cands in COL_ALIASES.items():
        m = find_match(cands)
        if m:
            resolved[canon] = m
    
    req = ["Destination IP Address", "Start Time", "End Time"]
    miss = [r for r in req if r not in resolved]
    if miss:
        raise ValueError(f"Missing required columns: {miss}. Available: {list(df.columns)}")
    return resolved


def parse_datetime_col(s: pd.Series, fmt: Optional[str]) -> pd.Series:
    """Parse datetime column with optional format."""
    if fmt:
        values = s.dropna().astype(str).str.strip()
        if values.empty:
            return pd.to_datetime(s, format=fmt, errors="coerce")

        # Detect day/month input even when the configured format is month/day.
        # A component greater than 12 makes the order unambiguous.
        date_parts = values.str.extract(r"^(\d{1,2})[/. -](\d{1,2})")
        first_parts = pd.to_numeric(date_parts[0], errors="coerce")
        second_parts = pd.to_numeric(date_parts[1], errors="coerce")
        if first_parts.gt(12).any() and second_parts.le(12).all():
            fmt = fmt.replace("%m", "__MONTH__").replace("%d", "%m").replace("__MONTH__", "%d")

        parsed = pd.to_datetime(s, format=fmt, errors="coerce")
        if parsed.notna().any() or s.dropna().empty:
            return parsed

        # Some detector exports use dots while others use slashes for the
        # same month/day/year timestamp format. Try the alternate separator
        # before treating the column as invalid.
        alternate_fmt = fmt.replace("/", ".") if "/" in fmt else fmt.replace(".", "/")
        if alternate_fmt != fmt:
            alternate = pd.to_datetime(s, format=alternate_fmt, errors="coerce")
            if alternate.notna().any():
                return alternate
        return parsed
    return pd.to_datetime(s, errors="coerce", infer_datetime_format=True)


def normalize_port(val) -> Optional[int]:
    """Normalize port values."""
    if pd.isna(val):
        return None
    s = str(val).strip().lower()
    if s in {"multiple", "unknown", "n/a", "na", "none", "0", ""}:
        return None
    try:
        return int(float(s))
    except Exception:
        return None


def max_risk_label(series: pd.Series) -> str:
    """Get the highest risk level from a series."""
    vals = [RISK_ORDER.get(str(x), 0) for x in series.dropna()]
    m = max(vals, default=0)
    return RISK_INV.get(m, "N/A")


def fmt_bps(bps) -> str:
    """Format bandwidth for display."""
    try:
        v = float(bps)
    except (TypeError, ValueError):
        return "N/A"
    if math.isnan(v) or v == 0:
        return "N/A"
    u = _BPS_UNIT
    if u == "Gbps":
        return f"{v/1e9:.2f} Gbps"
    if u == "Mbps":
        return f"{v/1e6:.2f} Mbps"
    if u == "Kbps":
        return f"{v/1e3:.1f} Kbps"
    if u == "bps":
        return f"{int(v)} bps"
    # auto: scale to best fit
    if v >= 1e9:
        return f"{v/1e9:.2f} Gbps"
    if v >= 1e6:
        return f"{v/1e6:.2f} Mbps"
    return f"{v/1e3:.1f} Kbps"


def fmt_pps(pps) -> str:
    """Format packet rate for display."""
    try:
        v = float(pps)
    except (TypeError, ValueError):
        return "N/A"
    if math.isnan(v) or v == 0:
        return "N/A"
    u = _PPS_UNIT
    if u == "Mpps":
        return f"{v/1e6:.2f}M pps"
    if u == "Kpps":
        return f"{v/1e3:.0f}K pps"
    if u == "pps":
        return f"{int(v)} pps"
    # auto: scale to best fit
    if v >= 1e6:
        return f"{v/1e6:.2f}M pps"
    if v >= 1e3:
        return f"{v/1e3:.0f}K pps"
    return f"{int(v)} pps"


def fmt_duration(mins) -> str:
    """Format duration in minutes."""
    try:
        v = float(mins)
    except (TypeError, ValueError):
        return "N/A"
    if math.isnan(v):
        return "N/A"
    total_m = int(round(v))
    if total_m >= 60:
        h, m = divmod(total_m, 60)
        return f"{h}h {m}m" if m else f"{h}h"
    return f"{total_m} min"


def _series_val(row: pd.Series, col: str) -> str:
    """Safely extract series value."""
    if col not in row.index:
        return "—"
    v = row[col]
    try:
        if pd.isna(v):
            return "—"
    except (TypeError, ValueError):
        pass
    return str(v)


def _attack_detail_dict(row: pd.Series) -> dict:
    """Extract attack details from a row."""
    def flt(col):
        if col not in row.index:
            return float("nan")
        try:
            return float(row[col])
        except (TypeError, ValueError):
            return float("nan")

    def ts(col):
        if col not in row.index:
            return "—"
        v = row[col]
        try:
            if pd.isna(v):
                return "—"
            return pd.Timestamp(v).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return str(v)

    return {
        "Target IP": _series_val(row, "Destination IP"),
        "Protocols": _series_val(row, "Protocols Seen"),
        "Peak Bandwidth": fmt_bps(flt("Peak bps")),
        "Peak PPS": fmt_pps(flt("Peak pps")),
        "Attack Start": ts("Attack Window Start"),
        "Attack End": ts("Attack Window End"),
        "Duration": fmt_duration(flt("Duration (mins)")),
        "Vectors": _series_val(row, "Vectors (Attack Names)"),
        "Policy": _series_val(row, "Policies"),
        "Devices": _series_val(row, "Devices Involved"),
    }


# ══════════════════════════════════════════════════════════════════
#  DefenseFlow External-Detector Log Parser
# ══════════════════════════════════════════════════════════════════

def find_dfc_support_sources(input_dir: Path) -> List[Path]:
    """Return all DefenseFlow archives/folders, newest first."""
    if not input_dir.exists():
        return []

    sources = list(input_dir.glob("dfc_support*.zip"))
    sources.extend(d for d in input_dir.glob("dfc_support*") if d.is_dir())

    def extract_timestamp(path: Path) -> str:
        match = re.search(r'(\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2})', path.name)
        return match.group(1) if match else ""

    return sorted(sources, key=extract_timestamp, reverse=True)


def is_detector_line(line_lower: str, detector_type: str) -> bool:
    """Return whether a log line belongs to the selected external detector."""
    detector_name = detector_type.lower()
    if detector_name == "kentik":
        return "kentik" in line_lower
    if detector_name == "arbor":
        return "arbor" in line_lower
    if detector_name == "defensepro":
        return "detection source type defense_pro" in line_lower
    return False


def is_activation_line(line_lower: str, activation_string: str) -> bool:
    """Match a configured detector activation substring."""
    activation_filter = activation_string.strip().lower()
    return bool(activation_filter) and activation_filter in line_lower


def parse_detector_raw_events(
    log_source: Union[Path, List[Path]],
    detector_type: str,
    activation_string: str = "",
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None
) -> list:
    """
    Parse detection logs to extract raw external-detector event details.
    Returns a list of dictionaries with event details.
    Supports both folders and ZIP files, including nested detection.*.log.zip files.
    Filters events by start_time and end_time if provided.
    """
    if isinstance(log_source, list):
        events = []
        for source in log_source:
            events.extend(parse_detector_raw_events(source, detector_type, activation_string, start_time, end_time))

        # Archives can overlap. Keep one copy of each detector event.
        unique_events = {}
        for event in events:
            key = (
                event["External_ID"], event["Event_Type"], event["Timestamp"],
                event["Network"], event["Protocol"], event["Bandwidth_bps"],
                event.get("Activation_Operation", ""),
                event["Raw_Log"] if event.get("Event_Type") == "activation" else ""
            )
            if key[0]:
                unique_events[key] = event
        return list(unique_events.values())

    events = []
    
    if not log_source or not log_source.exists():
        return []
    
    def parse_line(line: str) -> dict:
        """Helper to parse a single log line."""
        # Extract timestamp
        timestamp_match = re.match(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
        timestamp = timestamp_match.group(1) if timestamp_match else ""
        
        # Extract key fields using regex
        network_match = re.search(r'network\s+([\d\.\/]+)', line)
        protocol_match = re.search(r'protocol\s+(\w+)', line)
        external_id_match = re.search(
            r'(?:external ID|external attack ID)\s+([A-Za-z0-9_-]+)',
            line,
            re.IGNORECASE
        )
        bandwidth_match = re.search(r'bandwidth\s+([\d]+)\(bps\)', line)
        event_type_match = re.search(r'attack\s+(started|ended)', line)
        activation_match = re.search(r'triggered up operation\s+([^ ]+)', line, re.IGNORECASE)
        
        return {
            'Timestamp': timestamp,
            'Event_Type': (
                event_type_match.group(1) if event_type_match
                else "activation" if activation_match else ""
            ),
            'Activation_Operation': activation_match.group(1) if activation_match else "",
            'Network': network_match.group(1) if network_match else "",
            'Protocol': protocol_match.group(1) if protocol_match else "",
            'External_ID': external_id_match.group(1) if external_id_match else "",
            'Bandwidth_bps': bandwidth_match.group(1) if bandwidth_match else "",
            'Raw_Log': line.strip()
        }
    
    def process_log_content(content_bytes: bytes):
        """Helper to process log content and extract detector events."""
        try:
            content = content_bytes.decode('utf-8', errors='ignore')
            for line in content.split('\n'):
                line_lower = line.lower()
                detector_line = is_detector_line(line_lower, detector_type)
                activation_line = (
                    detector_type.lower() == "defensepro"
                    and "triggered up operation" in line_lower
                    and (
                        not activation_string
                        or is_activation_line(line_lower, activation_string)
                    )
                ) or (
                    bool(activation_string)
                    and is_activation_line(line_lower, activation_string)
                )
                if detector_line or activation_line:
                    event = parse_line(line)
                    
                    # Apply time filter
                    if event['Timestamp'] and (start_time or end_time):
                        try:
                            event_dt = datetime.strptime(event['Timestamp'], '%Y-%m-%d %H:%M:%S')
                            if start_time and event_dt < start_time:
                                continue
                            if end_time and event_dt > end_time:
                                continue
                        except:
                            pass  # Include events with unparseable timestamps
                    
                    events.append(event)
        except Exception as ex:
            pass  # Skip problematic lines
    
    # Handle ZIP file
    if log_source.suffix == '.zip':
        try:
            with zipfile.ZipFile(log_source, 'r') as zf:
                # Find all relevant log files and nested ZIPs
                main_logs = [
                    f for f in zf.namelist()
                    if ("detection.log" in f.lower() or "alert.log" in f.lower())
                    and not f.endswith('/')
                    and not f.lower().endswith('.zip')
                ]
                nested_zips = [f for f in zf.namelist() if (f.endswith('.log.zip')) and ('detection.' in f.lower() or 'alert.' in f.lower())]
                
                # Process main detection.log files
                for log_file in main_logs:
                    with zf.open(log_file) as f:
                        content = f.read()
                        process_log_content(content)
                
                # Process nested detection.*.log.zip and alert.*.log.zip files
                for nested_zip_name in nested_zips:
                    try:
                        with zf.open(nested_zip_name) as nested_zip_file:
                            nested_zip_data = nested_zip_file.read()
                            
                            # Open the nested ZIP
                            with zipfile.ZipFile(io.BytesIO(nested_zip_data)) as nested_zf:
                                # Get log files inside the nested ZIP
                                for nested_log in nested_zf.namelist():
                                    if not nested_log.endswith('/'):
                                        with nested_zf.open(nested_log) as f:
                                            content = f.read()
                                            process_log_content(content)
                    except Exception as ex:
                        pass  # Skip problematic nested ZIPs

                # A support bundle can contain another full support bundle
                # (commonly standby_support.zip) with older detection logs.
                support_zips = [
                    name for name in zf.namelist()
                    if name.lower().endswith("support.zip")
                ]
                for support_zip_name in support_zips:
                    try:
                        with zf.open(support_zip_name) as support_file:
                            with zipfile.ZipFile(io.BytesIO(support_file.read())) as support_zf:
                                support_logs = [
                                    name for name in support_zf.namelist()
                                    if ("detection.log" in name.lower() or "alert.log" in name.lower())
                                    and not name.endswith("/")
                                    and not name.lower().endswith(".zip")
                                ]
                                support_nested_zips = [
                                    name for name in support_zf.namelist()
                                    if name.lower().endswith(".log.zip")
                                    and ("detection." in name.lower() or "alert." in name.lower())
                                ]
                                for log_name in support_logs:
                                    process_log_content(support_zf.read(log_name))
                                for nested_name in support_nested_zips:
                                    with support_zf.open(nested_name) as nested_file:
                                        with zipfile.ZipFile(io.BytesIO(nested_file.read())) as nested_zf:
                                            for log_name in nested_zf.namelist():
                                                if not log_name.endswith('/'):
                                                    process_log_content(nested_zf.read(log_name))
                    except Exception as ex:
                        print(f"[WARN] Error reading nested support ZIP {support_zip_name}: {ex}")
                        
        except Exception as ex:
            print(f"[WARN] Error reading ZIP {log_source} for raw events: {ex}")
    
    # Handle folder
    else:
        log_files = list(log_source.glob("**/detection.log*"))
        
        for log_file in log_files:
            try:
                with open(log_file, 'rb') as f:
                    content = f.read()
                    process_log_content(content)
            except Exception as ex:
                print(f"[WARN] Error reading {log_file} for raw events: {ex}")
    
    return events


def create_detector_attack_cycles(events: list) -> list:
    """
    Match external-detector start and end events to create attack cycles.
    Returns a list of attack cycles with detailed information.
    """
    from datetime import datetime
    
    # Group events by external detector ID.
    events_by_id = defaultdict(list)
    for event in events:
        if event['External_ID']:
            events_by_id[event['External_ID']].append(event)
    
    cycles = []
    for kentik_id, event_list in sorted(events_by_id.items()):
        # Find start and end events
        starts = [e for e in event_list if e['Event_Type'] == 'started']
        ends = [e for e in event_list if e['Event_Type'] == 'ended']
        
        # Use first start and last end
        if starts:
            start_event = starts[0]
            end_event = ends[-1] if ends else None
            
            # Parse timestamps
            try:
                start_time = datetime.strptime(start_event['Timestamp'], '%Y-%m-%d %H:%M:%S')
                end_time = datetime.strptime(end_event['Timestamp'], '%Y-%m-%d %H:%M:%S') if end_event else None
            except:
                start_time = None
                end_time = None
            
            # Calculate duration
            duration_min = ""
            status = "Completed" if end_event else "Ongoing"
            if start_time and end_time:
                duration = (end_time - start_time).total_seconds() / 60
                duration_min = int(duration)
            
            # Format bandwidth
            bandwidth_bps = int(start_event['Bandwidth_bps']) if start_event['Bandwidth_bps'] else 0
            if bandwidth_bps > 0:
                if bandwidth_bps >= 1_000_000_000:
                    peak_bw = f"{bandwidth_bps / 1_000_000_000:.2f} Gbps"
                elif bandwidth_bps >= 1_000_000:
                    peak_bw = f"{bandwidth_bps / 1_000_000:.2f} Mbps"
                elif bandwidth_bps >= 1_000:
                    peak_bw = f"{bandwidth_bps / 1_000:.2f} Kbps"
                else:
                    peak_bw = f"{bandwidth_bps} bps"
            else:
                peak_bw = "0 bps"
            
            cycle = {
                'Detector_ID': kentik_id,
                'Status': status,
                'Target_Network': start_event['Network'],
                'Protocol': start_event['Protocol'],
                'Peak_Bandwidth': peak_bw,
                'Peak_Bandwidth_bps': bandwidth_bps,
                'Attack_Start': start_event['Timestamp'],
                'Attack_End': end_event['Timestamp'] if end_event else "",
                'Duration_min': duration_min,
                'Detection_Source': 'EXTERNAL_DETECTOR',
                'Event_Count': len(event_list)
            }
            cycles.append(cycle)
    
    return cycles


# ══════════════════════════════════════════════════════════════════
#  Time Filter Functions
# ══════════════════════════════════════════════════════════════════

def apply_time_filter(
    df: pd.DataFrame,
    cols: dict,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None
) -> pd.DataFrame:
    """Filter DataFrame by start time range."""
    if start_time is None and end_time is None:
        return df
    
    start_col = cols["Start Time"]
    mask = pd.Series([True] * len(df), index=df.index)
    
    if start_time:
        mask &= df[start_col] >= start_time
    
    if end_time:
        mask &= df[start_col] <= end_time
    
    filtered_df = df[mask].reset_index(drop=True)
    
    if start_time or end_time:
        start_str = start_time.strftime("%Y-%m-%d %H:%M:%S") if start_time else "beginning"
        end_str = end_time.strftime("%Y-%m-%d %H:%M:%S") if end_time else "now"
        print(f"[INFO] Time filter applied: {start_str} → {end_str}")
        print(f"[INFO] Rows after filter: {len(filtered_df)} (filtered out: {len(df) - len(filtered_df)})")
    
    return filtered_df


def read_time_filter_from_config(cfg: configparser.ConfigParser) -> tuple:
    """Read time filter settings from config. Returns (start_time, end_time)."""
    if not cfg.has_section("time_filter"):
        return None, None
    
    start_time = None
    end_time = None
    
    # Try fixed date range
    start_str = cfg.get("time_filter", "start", fallback="").strip()
    end_str = cfg.get("time_filter", "end", fallback="").strip()
    
    if start_str:
        parsed_start = pd.to_datetime(start_str, errors="coerce")
        if pd.isna(parsed_start):
            print(f"[WARN] Could not parse start time: {start_str}")
        else:
            start_time = parsed_start.to_pydatetime()
    
    if end_str:
        parsed_end = pd.to_datetime(end_str, errors="coerce")
        if pd.isna(parsed_end):
            print(f"[WARN] Could not parse end time: {end_str}")
        else:
            end_time = parsed_end.to_pydatetime()
            # A date-only end value should include the entire calendar day.
            if re.fullmatch(r"\d{4}-\d{2}-\d{2}", end_str):
                end_time = end_time.replace(hour=23, minute=59, second=59)
    
    # Try relative time filters (only if fixed range not set)
    if not start_time and not end_time:
        last_hours_str = cfg.get("time_filter", "last_hours", fallback="").strip()
        last_days_str = cfg.get("time_filter", "last_days", fallback="").strip()
        
        if last_hours_str:
            try:
                hours = float(last_hours_str)
                end_time = datetime.now()
                start_time = end_time - timedelta(hours=hours)
            except ValueError:
                print(f"[WARN] Invalid last_hours value: {last_hours_str}")
        elif last_days_str:
            try:
                days = float(last_days_str)
                end_time = datetime.now()
                start_time = end_time - timedelta(days=days)
            except ValueError:
                print(f"[WARN] Invalid last_days value: {last_days_str}")
    
    return start_time, end_time


# ══════════════════════════════════════════════════════════════════
#  Campaign Grouping Logic
# ══════════════════════════════════════════════════════════════════

def group_campaigns_by_dst(
    df: pd.DataFrame,
    cols: dict,
    gap_minutes: int,
    split_by_port: bool = False
) -> pd.DataFrame:
    """Group attacks into campaigns by destination IP and time windows."""
    w = df.copy()
    if "Destination Port" in cols:
        w["_DestPortNorm"] = w[cols["Destination Port"]].apply(normalize_port)
    else:
        w["_DestPortNorm"] = np.nan

    key_cols = [cols["Destination IP Address"]]
    if split_by_port:
        key_cols.append("_DestPortNorm")

    w = w.sort_values(key_cols + [cols["Start Time"]])

    campaigns = []
    for key, grp in w.groupby(key_cols, dropna=False):
        grp = grp.sort_values(cols["Start Time"])
        current = None
        for _, r in grp.iterrows():
            st = r[cols["Start Time"]]
            et = r[cols["End Time"]]
            if pd.isna(st) or pd.isna(et):
                continue
            if current is None:
                current = {
                    "Destination IP": r[cols["Destination IP Address"]],
                    "PortKey": r.get("_DestPortNorm", None) if split_by_port else None,
                    "Window Start": st,
                    "Window End": et,
                    "Events": [r],
                }
                continue
            gap = st - current["Window End"]
            if gap <= timedelta(minutes=gap_minutes):
                if et > current["Window End"]:
                    current["Window End"] = et
                current["Events"].append(r)
            else:
                campaigns.append(current)
                current = {
                    "Destination IP": r[cols["Destination IP Address"]],
                    "PortKey": r.get("_DestPortNorm", None) if split_by_port else None,
                    "Window Start": st,
                    "Window End": et,
                    "Events": [r],
                }
        if current is not None:
            campaigns.append(current)

    rows = []
    for c in campaigns:
        edf = pd.DataFrame(c["Events"])
        devices = sorted(set(edf.get(cols.get("Device IP Address", "Device IP Address"), pd.Series(dtype="object")).dropna().astype(str)))
        protocols = sorted(set(edf.get(cols.get("Protocol", "Protocol"), pd.Series(dtype="object")).dropna().astype(str)))
        cats = sorted(set(edf.get(cols.get("Threat Category", "Threat Category"), pd.Series(dtype="object")).dropna().astype(str)))
        names = sorted(set(edf.get(cols.get("Attack Name", "Attack Name"), pd.Series(dtype="object")).dropna().astype(str)))
        policies = sorted(set(edf.get(cols.get("Policy Name", "Policy Name"), pd.Series(dtype="object")).dropna().astype(str))) if ("Policy Name" in cols) else []
        ports = [int(p) for p in edf.get("_DestPortNorm", pd.Series(dtype="float")).dropna().unique()] if "_DestPortNorm" in edf.columns else []
        dest_ports_label = ",".join(map(str, sorted(ports))) if ports else "Multiple/Unknown"
        total_pkts = edf.get(cols.get("Total Packets Dropped", "Total Packets Dropped"), pd.Series(dtype="float")).sum(skipna=True)
        peak_pps = edf.get(cols.get("Max pps", "Max pps"), pd.Series(dtype="float")).max(skipna=True)
        peak_bps = edf.get(cols.get("Max bps", "Max bps"), pd.Series(dtype="float")).max(skipna=True)
        risk = max_risk_label(edf.get(cols.get("Risk", "Risk"), pd.Series(dtype="object")))

        rows.append({
            "Attack Window Start": c["Window Start"],
            "Attack Window End": c["Window End"],
            "Duration (mins)": round((c["Window End"] - c["Window Start"]).total_seconds() / 60.0, 2),
            "Destination IP": c["Destination IP"],
            "# Events": int(edf.shape[0]),
            "Peak pps": float(peak_pps) if not math.isnan(peak_pps) else np.nan,
            "Peak bps": float(peak_bps) if not math.isnan(peak_bps) else np.nan,
            "Threat Categories": ", ".join(cats) if cats else "N/A",
            "Vectors (Attack Names)": "; ".join(names) if names else "N/A",
            "Protocols Seen": ", ".join(protocols) if protocols else "N/A",
            "Dest Ports": dest_ports_label,
            "Total Packets Dropped": int(total_pkts) if not math.isnan(total_pkts) else np.nan,
            "Devices Involved": ", ".join(devices) if devices else "N/A",
            "Policies": "; ".join(policies) if policies else "N/A",
            "Max Risk": risk,
        })

    out = pd.DataFrame(rows).sort_values(["Attack Window Start", "Destination IP"]).reset_index(drop=True)
    return out


# ══════════════════════════════════════════════════════════════════
#  HTML Report Generator
# ══════════════════════════════════════════════════════════════════

def generate_html_report(
    campaign_df: pd.DataFrame,
    output_dir: Path,
    ts: str,
    title: str = "Radware Attack Report",
    detector_type: str = "",
    activation_string: str = "",
    report_period: str = "weekly",
    log_dir: Optional[Union[Path, List[Path]]] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    total_events: Optional[int] = None,
    raw_events_df: Optional[pd.DataFrame] = None
) -> Optional[Path]:
    """Generate a comprehensive HTML report with weekly or monthly trends."""
    
    df = campaign_df.copy()
    df["Attack Window Start"] = pd.to_datetime(df["Attack Window Start"], errors="coerce")
    df["Attack Window End"] = pd.to_datetime(df.get("Attack Window End", pd.Series(dtype="datetime64[ns]")), errors="coerce")
    df = df.dropna(subset=["Attack Window Start"])
    
    if df.empty:
        print("[WARN] No data – HTML report not generated.")
        return None

    period_start = df["Attack Window Start"].min()
    period_end = (
        df["Attack Window End"].max()
        if "Attack Window End" in df.columns and df["Attack Window End"].notna().any()
        else df["Attack Window Start"].max()
    )

    has_bps = "Peak bps" in df.columns and df["Peak bps"].notna().any()
    has_pps = "Peak pps" in df.columns and df["Peak pps"].notna().any()
    has_dur = "Duration (mins)" in df.columns

    # ── Unit helpers for charts ────────────────────────────────────
    _bw_chart_div, _bw_chart_lbl, _bw_tick_cb = {
        "Gbps": (1e9, "Gbps", "v => v.toFixed(2) + ' G'"),
        "Mbps": (1e6, "Mbps", "v => v.toFixed(1) + ' M'"),
        "Kbps": (1e3, "Kbps", "v => v.toFixed(0) + ' K'"),
        "bps": (1, "bps", "v => v.toFixed(0)"),
    }.get(_BPS_UNIT, (1e9, "Gbps", "v => v.toFixed(2) + ' G'"))

    _pps_chart_div, _pps_chart_lbl, _pps_tick_cb = {
        "Mpps": (1e6, "M pps", "v => v.toFixed(2) + 'M'"),
        "Kpps": (1e3, "K pps", "v => v.toFixed(0) + 'K'"),
        "pps": (1, "pps", "v => v.toFixed(0)"),
    }.get(_PPS_UNIT, (1e3, "K pps", "v => v.toFixed(0) + 'K'"))

    period_label = "Monthly" if report_period == "monthly" else "Weekly"
    period_unit = "Month" if report_period == "monthly" else "Week"

    def trend_period_start(timestamp):
        if report_period == "monthly":
            return timestamp.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

        month_start = timestamp.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        week_start = timestamp.to_period("W-SUN").start_time
        if week_start.month != timestamp.month:
            return month_start
        return week_start

    scope_start = pd.Timestamp(start_time) if start_time is not None else df["Attack Window Start"].min()
    scope_end = pd.Timestamp(end_time) if end_time is not None else df["Attack Window End"].max()
    if pd.isna(scope_end):
        scope_end = df["Attack Window Start"].max()

    # Build all calendar periods in the selected scope, including periods
    # with no campaigns so the charts show explicit zero activity.
    period_starts = []
    cursor = trend_period_start(scope_start)
    while cursor <= scope_end:
        period_starts.append(cursor)
        if report_period == "monthly":
            cursor = (cursor.replace(day=28) + timedelta(days=4)).replace(day=1)
        elif cursor.day == 1:
            first_week_end = cursor + timedelta(days=6 - cursor.weekday())
            cursor = first_week_end + timedelta(days=1)
        else:
            cursor += timedelta(days=7)

    # Group trends by the selected report period.
    df["_wstart"] = df["Attack Window Start"].apply(trend_period_start)

    # Build event count mapping by week if raw events provided
    event_counts_by_week = {}
    if raw_events_df is not None and not raw_events_df.empty:
        raw_df = raw_events_df.copy()
        # Ensure datetime column exists
        if "Attack Window Start" in raw_df.columns:
            raw_df["Attack Window Start"] = pd.to_datetime(raw_df["Attack Window Start"], errors="coerce")
            raw_df = raw_df.dropna(subset=["Attack Window Start"])
            raw_df["_wstart"] = raw_df["Attack Window Start"].apply(trend_period_start)
            event_counts_by_week = raw_df.groupby("_wstart").size().to_dict()

    grouped_periods = {wstart: wgrp for wstart, wgrp in df.groupby("_wstart", sort=True)}
    period_rows = []
    for wstart in period_starts:
        wgrp = grouped_periods.get(wstart, df.iloc[0:0])
        if report_period == "monthly":
            label = wstart.strftime("%B %Y")
        else:
            month_start = wstart.replace(day=1)
            first_week_end = month_start + timedelta(days=6 - month_start.weekday())
            next_month = (month_start.replace(day=28) + timedelta(days=4)).replace(day=1)
            month_end = next_month - timedelta(days=1)
            wend = first_week_end if wstart == month_start else min(wstart + timedelta(days=6), month_end)
            wn = 1 if wstart == month_start else 2 + ((wstart.day - first_week_end.day - 1) // 7)
            label = (
                f"{wstart.strftime('%b')} Wk{wn}\u00a0\u00a0"
                f"{wstart.strftime('%b %d')}\u2013{wend.strftime('%b %d')}"
            )
        cnt = len(wgrp)  # campaign count
        event_cnt = event_counts_by_week.get(wstart, cnt)  # event count (fallback to campaign count)
        mx_bps = wgrp["Peak bps"].max(skipna=True) if has_bps else float("nan")
        mx_pps = wgrp["Peak pps"].max(skipna=True) if has_pps else float("nan")
        vc = wgrp["Destination IP"].value_counts()
        top_dst, top_cnt = (str(vc.idxmax()), int(vc.max())) if not vc.empty else ("N/A", 0)

        if has_dur and wgrp["Duration (mins)"].notna().any():
            li = wgrp["Duration (mins)"].idxmax()
            lr = wgrp.loc[li]
            lng_dst = str(lr["Destination IP"])
            lng_dur = fmt_duration(lr["Duration (mins)"])
            lng_start = lr["Attack Window Start"].strftime("%Y-%m-%d %H:%M:%S")
        else:
            lng_dst = lng_dur = lng_start = "N/A"

        period_rows.append({
            "label": label,
            "count": cnt,
            "event_count": event_cnt,
            "max_bps": mx_bps,
            "max_pps": mx_pps,
            "top_dst": top_dst,
            "top_cnt": top_cnt,
            "lng_dst": lng_dst,
            "lng_dur": lng_dur,
            "lng_start": lng_start,
        })

    # ── Statistics ─────────────────────────────────────────────────
    total_attacks = len(df)  # Total campaigns
    total_events_count = len(raw_events_df) if raw_events_df is not None else (
        total_events if total_events is not None else total_attacks
    )
    num_periods = len(period_rows)
    most_tgt_vc = df["Destination IP"].value_counts()
    most_tgt = str(most_tgt_vc.idxmax())
    most_tgt_count = int(most_tgt_vc.max())
    global_max_bps = df["Peak bps"].max(skipna=True) if has_bps else float("nan")
    global_max_pps = df["Peak pps"].max(skipna=True) if has_pps else float("nan")

    bps_notna = df["Peak bps"].dropna() if has_bps else pd.Series(dtype=float)
    pps_notna = df["Peak pps"].dropna() if has_pps else pd.Series(dtype=float)
    bw_detail = _attack_detail_dict(df.loc[bps_notna.idxmax()]) if not bps_notna.empty else {}
    pps_detail = _attack_detail_dict(df.loc[pps_notna.idxmax()]) if not pps_notna.empty else {}

    # Attack type distribution
    all_vectors = []
    for vectors_str in df["Vectors (Attack Names)"].dropna():
        all_vectors.extend([v.strip() for v in str(vectors_str).split(";")])
    vector_counts = pd.Series(all_vectors).value_counts().head(10)

    # Parse and save raw detector events and matched attack cycles.
    detector_activations = {}
    if log_dir:
        detector_raw_events = parse_detector_raw_events(
            log_dir, detector_type, activation_string, start_time, end_time
        )
        if detector_raw_events:
            detector_prefix = detector_type.capitalize()
            # Save individual events
            raw_csv_path = output_dir / f"{detector_prefix}_Radware_Raw_Events_{ts}.csv"
            raw_df = pd.DataFrame(detector_raw_events)
            raw_df.to_csv(raw_csv_path, index=False, encoding='utf-8')
            print(f"[INFO] {detector_prefix} raw events CSV saved: {raw_csv_path} ({len(detector_raw_events)} events)")
            
            # Create and save attack cycles (matched start/end events)
            attack_cycles = create_detector_attack_cycles(detector_raw_events)
            if attack_cycles:
                cycles_csv_path = output_dir / f"{detector_prefix}_Radware_Attack_Cycles_{ts}.csv"
                cycles_df = pd.DataFrame(attack_cycles)
                cycles_df.to_csv(cycles_csv_path, index=False, encoding='utf-8')
                print(f"[INFO] {detector_prefix} attack cycles CSV saved: {cycles_csv_path} ({len(attack_cycles)} cycles)")

                activation_events = [
                    event for event in detector_raw_events
                    if event.get("Event_Type") == "activation"
                    and event.get("External_ID")
                ]
                if detector_type.lower() == "defensepro" and activation_events:
                    if not activation_string:
                        operation_counts = Counter(
                            event.get("Activation_Operation", "")
                            for event in activation_events
                        )
                        activation_string = operation_counts.most_common(1)[0][0]
                        print(f"[INFO] Auto-selected DefensePro activation operation: {activation_string}")
                    activation_events = [
                        event for event in activation_events
                        if event.get("Activation_Operation", "").lower()
                        == activation_string.lower()
                    ]

                if detector_type.lower() == "defensepro" and activation_events:
                    for event in activation_events:
                        date_str = event["Timestamp"][:10]
                        detector_activations[date_str] = detector_activations.get(date_str, 0) + 1
                else:
                    # Kentik and Arbor activations are derived from cycles.
                    for cycle in attack_cycles:
                        date_str = cycle["Attack_Start"][:10]
                        detector_activations[date_str] = detector_activations.get(date_str, 0) + 1

    # Save detector activation summary to CSV.
    if detector_activations:
        detector_prefix = detector_type.capitalize()
        activation_csv_path = output_dir / f"{detector_prefix}_Radware_Activations_{ts}.csv"
        activation_df = pd.DataFrame([
            {"Date": date, "Activation_Count": count}
            for date, count in sorted(detector_activations.items())
        ])
        activation_df.to_csv(activation_csv_path, index=False, encoding='utf-8')
        print(f"[INFO] {detector_prefix} activations CSV saved: {activation_csv_path}")
    
    # Prepare detector activation data for chart (sorted by date).
    if detector_activations:
        sorted_dates = sorted(detector_activations.keys())
        detector_dates = [datetime.strptime(d, "%Y-%m-%d").strftime("%b %d") for d in sorted_dates]
        detector_counts = [detector_activations[d] for d in sorted_dates]
    else:
        detector_dates = []
        detector_counts = []
    detector_activation_total = sum(detector_counts)

    # ── JS data ────────────────────────────────────────────────────
    labels_js = json.dumps([w["label"] for w in period_rows], ensure_ascii=False)
    counts_js = json.dumps([w["event_count"] for w in period_rows])
    bw_gbps_js = json.dumps([
        round(w["max_bps"] / _bw_chart_div, 2) if not math.isnan(w["max_bps"]) else 0
        for w in period_rows
    ])
    pps_k_js = json.dumps([
        round(w["max_pps"] / _pps_chart_div, 2) if not math.isnan(w["max_pps"]) else 0
        for w in period_rows
    ])
    dst_ips_js = json.dumps([w["top_dst"] for w in period_rows])
    dst_cnt_js = json.dumps([w["top_cnt"] for w in period_rows])
    bw_detail_js = json.dumps(bw_detail, ensure_ascii=False)
    pps_detail_js = json.dumps(pps_detail, ensure_ascii=False)

    # Vector distribution for pie chart
    vector_labels_js = json.dumps(vector_counts.index.tolist()[:8], ensure_ascii=False)
    vector_values_js = json.dumps(vector_counts.values.tolist()[:8])

    # External-detector activation data.
    detector_dates_js = json.dumps(detector_dates, ensure_ascii=False)
    detector_counts_js = json.dumps(detector_counts)

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    period_str = f"{period_start.strftime('%Y-%m-%d')}  →  {period_end.strftime('%Y-%m-%d')}"

    # ── Overview cards ─────────────────────────────────────────────
    bw_card = (
        f'<div class="stat-card clickable" onclick="showDetail(\'bw\')" title="Click for details">'
        f'<div class="stat-value large-text">{fmt_bps(global_max_bps)}</div>'
        f'<div class="stat-label">Peak Bandwidth</div>'
        f'<div class="stat-sub">&#128269; click for details</div></div>'
    ) if not math.isnan(global_max_bps) else ""

    pps_card = (
        f'<div class="stat-card clickable" onclick="showDetail(\'pps\')" title="Click for details">'
        f'<div class="stat-value large-text">{fmt_pps(global_max_pps)}</div>'
        f'<div class="stat-label">Peak PPS</div>'
        f'<div class="stat-sub">&#128269; click for details</div></div>'
    ) if not math.isnan(global_max_pps) else ""

    # ── Table rows ─────────────────────────────────────────────────
    trows = []
    for i, w in enumerate(period_rows):
        cls = "even" if i % 2 == 0 else "odd"
        trows.append(
            f'<tr class="{cls}">'
            f'<td class="week-col"><strong>{w["label"]}</strong></td>'
            f'<td class="num-col">{w["event_count"]}</td>'
            f'<td>{fmt_bps(w["max_bps"])}</td>'
            f'<td>{fmt_pps(w["max_pps"])}</td>'
            f'<td class="ip-col">{w["top_dst"]}<span class="badge">{w["top_cnt"]}x</span></td>'
            f'<td class="ip-col">{w["lng_dst"]}<br>'
            f'<span class="sub">{w["lng_dur"]} &middot; {w["lng_start"]}</span></td>'
            f'</tr>'
        )
    table_rows_html = "\n".join(trows)

    # ── Top 10 Attacks Table ───────────────────────────────────────
    top_attacks = df.nlargest(10, "Peak bps") if has_bps else df.head(10)
    attack_rows = []
    for i, (idx, row) in enumerate(top_attacks.iterrows()):
        cls = "even" if i % 2 == 0 else "odd"
        attack_rows.append(
            f'<tr class="{cls}">'
            f'<td class="ip-col">{row["Destination IP"]}</td>'
            f'<td>{row["Attack Window Start"].strftime("%Y-%m-%d %H:%M")}</td>'
            f'<td>{fmt_duration(row.get("Duration (mins)", 0))}</td>'
            f'<td>{fmt_bps(row.get("Peak bps", 0))}</td>'
            f'<td>{fmt_pps(row.get("Peak pps", 0))}</td>'
            f'<td class="vector-col">{row.get("Vectors (Attack Names)", "N/A")[:50]}...</td>'
            f'</tr>'
        )
    attack_table_html = "\n".join(attack_rows)

    # ══════════════════════════════════════════════════════════════
    #  Full HTML Template
    # ══════════════════════════════════════════════════════════════

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f0f2f5; color: #2c3e50; line-height: 1.6;
        }}
        .container {{
            max-width: 1400px; margin: 0 auto; background: #fff;
            box-shadow: 0 4px 24px rgba(0,0,0,.12); border-radius: 10px; overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #003f7f 0%, #005bb5 60%, #0073e6 100%);
            color: #fff; padding: 36px 40px 28px;
        }}
        .header h1 {{ font-size: 28px; font-weight: 700; letter-spacing: .5px; }}
        .header .subtitle {{ margin-top: 8px; font-size: 14px; opacity: .85; }}
        .header .meta {{ margin-top: 14px; font-size: 12px; opacity: .7; display: flex; gap: 30px; flex-wrap: wrap; }}
        .header .meta span {{ display: flex; align-items: center; gap: 6px; }}
        .content {{ padding: 32px 40px; }}
        .section {{ margin-bottom: 40px; }}
        .section-title {{
            font-size: 18px; font-weight: 700; color: #003f7f;
            border-left: 4px solid #0073e6; padding-left: 12px; margin-bottom: 18px;
        }}
        .stats-grid {{
            display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px; margin-bottom: 8px;
        }}
        .stat-card {{
            background: #f7f9fc; border: 1px solid #dde3ef; border-radius: 8px;
            padding: 20px 18px; text-align: center; transition: box-shadow .2s;
        }}
        .stat-card:hover {{ box-shadow: 0 4px 14px rgba(0,63,127,.12); }}
        .stat-value {{ font-size: 28px; font-weight: 800; color: #003f7f; line-height: 1.1; }}
        .stat-value.large-text {{ font-size: 18px; }}
        .stat-value.xlarge-text {{ font-size: 14px; word-break: break-all; }}
        .stat-label {{ font-size: 12px; color: #6c757d; margin-top: 6px; text-transform: uppercase; letter-spacing: .6px; }}
        .stat-sub {{ font-size: 11px; color: #999; margin-top: 3px; }}
        .chart-row {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 24px; margin-bottom: 8px; }}
        .chart-box {{ background: #f7f9fc; border: 1px solid #dde3ef; border-radius: 8px; padding: 20px; }}
        .chart-title {{ font-size: 13px; font-weight: 600; color: #003f7f; margin-bottom: 14px; text-align: center; }}
        .chart-total {{ font-size: 12px; color: #555; text-align: center; margin: -4px 0 12px; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
        thead tr {{ background: #003f7f; color: #fff; }}
        thead th {{ padding: 11px 14px; text-align: left; font-weight: 600; white-space: nowrap; }}
        tbody tr.even {{ background: #f7f9fc; }}
        tbody tr.odd {{ background: #fff; }}
        tbody tr:hover {{ background: #e8f0fa; }}
        tbody td {{ padding: 10px 14px; border-bottom: 1px solid #e9ecef; vertical-align: top; }}
        .week-col {{ font-size: 12px; white-space: nowrap; }}
        .num-col {{ text-align: right; font-weight: 700; color: #003f7f; }}
        .ip-col {{ font-family: 'Consolas', monospace; font-size: 12px; }}
        .vector-col {{ font-size: 11px; color: #555; }}
        .badge {{
            display: inline-block; background: #0073e6; color: #fff;
            border-radius: 10px; padding: 1px 7px; font-size: 11px;
            margin-left: 6px; font-family: 'Segoe UI', sans-serif;
        }}
        .sub {{ font-size: 11px; color: #888; }}
        .clickable {{
            cursor: pointer; border: 1px solid #b0c8ef !important;
            transition: box-shadow .2s, transform .15s;
        }}
        .clickable:hover {{ box-shadow: 0 6px 20px rgba(0,63,127,.20) !important; transform: translateY(-2px); }}
        .modal-backdrop {{
            display: none; position: fixed; inset: 0;
            background: rgba(0,0,0,.45); z-index: 1000;
            align-items: center; justify-content: center;
        }}
        .modal-backdrop.open {{ display: flex; }}
        .modal {{
            background: #fff; border-radius: 10px; width: 520px; max-width: 95vw;
            box-shadow: 0 16px 48px rgba(0,0,0,.28); overflow: hidden;
        }}
        .modal-header {{
            background: linear-gradient(135deg, #003f7f, #0073e6);
            color: #fff; padding: 16px 20px; display: flex; align-items: center; justify-content: space-between;
        }}
        .modal-header h3 {{ font-size: 15px; font-weight: 700; }}
        .modal-close {{
            background: none; border: none; color: #fff; font-size: 22px;
            cursor: pointer; line-height: 1; padding: 0 4px;
        }}
        .modal-body {{ padding: 20px 24px; }}
        .detail-table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
        .detail-table td {{ padding: 7px 10px; border-bottom: 1px solid #eee; }}
        .detail-table td:first-child {{ color: #555; font-weight: 600; width: 38%; white-space: nowrap; }}
        .detail-table td:last-child {{ font-family: Consolas, monospace; color: #003f7f; word-break: break-word; }}
        .footer {{
            background: #f0f2f5; border-top: 1px solid #dde3ef;
            padding: 16px 40px; font-size: 11px; color: #888;
        }}
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>{title}</h1>
        <div class="subtitle">Comprehensive DDoS Attack Analysis &amp; Campaign Tracking</div>
        <div class="meta">
            <span>&#128197; Period: <strong>{period_str}</strong></span>
            <span>&#128344; Generated: {now_str}</span>
        </div>
    </div>

    <div class="content">
        <!-- Overview Section -->
        <div class="section">
            <div class="section-title">&#128202; Executive Overview</div>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value">{total_events_count}</div>
                    <div class="stat-label">Total Attack Events</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{num_periods}</div>
                    <div class="stat-label">{period_label} Periods Analyzed</div>
                </div>
                {bw_card}
                {pps_card}
                <div class="stat-card">
                    <div class="stat-value xlarge-text">{most_tgt}</div>
                    <div class="stat-label">Most Targeted IP</div>
                    <div class="stat-sub">{most_tgt_count} campaigns</div>
                </div>
            </div>
        </div>

        <!-- Period Trends Charts -->
        <div class="section">
            <div class="section-title">&#128200; {period_label} Attack Trends</div>
            <div class="chart-row">
                <div class="chart-box">
                    <div class="chart-title">Attack Events per {period_unit}</div>
                    <canvas id="chartCount"></canvas>
                </div>
                <div class="chart-box">
                    <div class="chart-title">Max Peak Bandwidth per {period_unit} ({_bw_chart_lbl})</div>
                    <canvas id="chartBW"></canvas>
                </div>
                <div class="chart-box">
                    <div class="chart-title">Max Peak PPS per {period_unit} ({_pps_chart_lbl})</div>
                    <canvas id="chartPPS"></canvas>
                </div>
                <div class="chart-box">
                    <div class="chart-title">Top DST IP Hit Count per {period_unit}</div>
                    <canvas id="chartDST"></canvas>
                </div>
            </div>
        </div>

        <!-- Attack Type Distribution -->
        <div class="section">
            <div class="section-title">&#128737; Attack Analysis</div>
            <div class="chart-row">
                <div class="chart-box">
                    <div class="chart-title">Top Attack Vectors</div>
                    <canvas id="chartVectors"></canvas>
                </div>
                <div class="chart-box">
                    <div class="chart-title">DefenseFlow Activation Count</div>
                    <div class="chart-total"><strong>Total Activations:</strong> {detector_activation_total:,}</div>
                    <canvas id="chartDetectorActivations"></canvas>
                </div>
            </div>
        </div>

        <!-- Top 10 Attacks -->
        <div class="section">
            <div class="section-title">&#128293; Top 10 Attacks by Bandwidth</div>
            <div style="overflow-x:auto">
                <table>
                    <thead>
                        <tr>
                            <th>Target IP</th>
                            <th>Start Time</th>
                            <th>Duration</th>
                            <th>Peak BW</th>
                            <th>Peak PPS</th>
                            <th>Attack Vectors</th>
                        </tr>
                    </thead>
                    <tbody>
{attack_table_html}
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Period Detail -->
        <div class="section">
            <div class="section-title">&#128197; {period_label} Summary</div>
            <div style="overflow-x:auto">
                <table>
                    <thead>
                        <tr>
                            <th>Week</th>
                            <th style="text-align:right">Events</th>
                            <th>Max Peak BW</th>
                            <th>Max Peak PPS</th>
                            <th>Top DST IP (count)</th>
                            <th>Longest Attack</th>
                        </tr>
                    </thead>
                    <tbody>
{table_rows_html}
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <div class="footer">
        <span>{title} &mdash; Generated {now_str}</span>
    </div>
</div>

<!-- Modal for Attack Details -->
<div class="modal-backdrop" id="modalBackdrop" onclick="hideModal(event)">
    <div class="modal">
        <div class="modal-header">
            <h3 id="modalTitle">Attack Detail</h3>
            <button class="modal-close" onclick="closeModal()">&#x2715;</button>
        </div>
        <div class="modal-body">
            <table class="detail-table" id="modalTable"></table>
        </div>
    </div>
</div>

<script>
const LABELS = {labels_js};
const COUNTS = {counts_js};
const BW_GBPS = {bw_gbps_js};
const PPS_K = {pps_k_js};
const DST_CNT = {dst_cnt_js};
const DST_IPS = {dst_ips_js};
const BW_DETAIL = {bw_detail_js};
const PPS_DETAIL = {pps_detail_js};
const VECTOR_LABELS = {vector_labels_js};
const VECTOR_VALUES = {vector_values_js};
const DETECTOR_DATES = {detector_dates_js};
const DETECTOR_COUNTS = {detector_counts_js};

function showDetail(type) {{
    const detail = type === 'bw' ? BW_DETAIL : PPS_DETAIL;
    const title = type === 'bw' ? '&#9889; Peak Bandwidth Attack Detail' : '&#128246; Peak PPS Attack Detail';
    document.getElementById('modalTitle').innerHTML = title;
    const tbl = document.getElementById('modalTable');
    tbl.innerHTML = Object.entries(detail)
        .map(([k, v]) => `<tr><td>${{k}}</td><td>${{v || '\u2014'}}</td></tr>`)
        .join('');
    document.getElementById('modalBackdrop').classList.add('open');
}}
function closeModal() {{ document.getElementById('modalBackdrop').classList.remove('open'); }}
function hideModal(e) {{ if (e.target === document.getElementById('modalBackdrop')) closeModal(); }}
document.addEventListener('keydown', e => {{ if (e.key === 'Escape') closeModal(); }});

const BLUE_PALETTE = [
    'rgba(0,63,127,0.78)', 'rgba(0,115,230,0.78)',
    'rgba(0,163,224,0.78)', 'rgba(0,191,255,0.78)',
    'rgba(0,214,198,0.78)', 'rgba(0,230,160,0.78)',
];
function barColor(n) {{ return Array.from({{length: n}}, (_, i) => BLUE_PALETTE[i % BLUE_PALETTE.length]); }}

const commonOpts = {{
    responsive: true,
    plugins: {{ legend: {{ display: false }}, tooltip: {{ mode: 'index', intersect: false }} }},
    scales: {{
        x: {{ ticks: {{ font: {{ size: 11 }}, maxRotation: 35 }}, grid: {{ color: 'rgba(0,0,0,.05)' }} }},
        y: {{ beginAtZero: true, ticks: {{ font: {{ size: 11 }} }}, grid: {{ color: 'rgba(0,0,0,.05)' }} }},
    }},
}};

// Period trend charts
new Chart(document.getElementById('chartCount'), {{
    type: 'bar',
    data: {{ labels: LABELS, datasets: [{{ label: 'Events', data: COUNTS, backgroundColor: barColor(LABELS.length), borderRadius: 5 }}] }},
    options: commonOpts,
}});

new Chart(document.getElementById('chartBW'), {{
    type: 'bar',
    data: {{ labels: LABELS, datasets: [{{ label: '{_bw_chart_lbl}', data: BW_GBPS, backgroundColor: barColor(LABELS.length), borderRadius: 5 }}] }},
    options: {{ ...commonOpts, scales: {{ ...commonOpts.scales, y: {{ ...commonOpts.scales.y, ticks: {{ ...commonOpts.scales.y.ticks, callback: {_bw_tick_cb} }} }} }} }},
}});

new Chart(document.getElementById('chartPPS'), {{
    type: 'bar',
    data: {{ labels: LABELS, datasets: [{{ label: '{_pps_chart_lbl}', data: PPS_K, backgroundColor: barColor(LABELS.length), borderRadius: 5 }}] }},
    options: {{ ...commonOpts, scales: {{ ...commonOpts.scales, y: {{ ...commonOpts.scales.y, ticks: {{ ...commonOpts.scales.y.ticks, callback: {_pps_tick_cb} }} }} }} }},
}});

new Chart(document.getElementById('chartDST'), {{
    type: 'bar',
    data: {{ labels: DST_IPS, datasets: [{{ label: 'Attacks on top DST IP', data: DST_CNT, backgroundColor: barColor(LABELS.length), borderRadius: 5 }}] }},
    options: {{
        ...commonOpts,
        plugins: {{ ...commonOpts.plugins, tooltip: {{ callbacks: {{
            title: items => DST_IPS[items[0].dataIndex],
            beforeLabel: ctx => 'Week: ' + LABELS[ctx.dataIndex],
            label: ctx => 'Hit count: ' + ctx.parsed.y,
        }} }} }},
        scales: {{ ...commonOpts.scales,
            x: {{ ...commonOpts.scales.x, ticks: {{ font: {{ size: 11 }}, maxRotation: 35 }} }},
            y: {{ ...commonOpts.scales.y, ticks: {{ ...commonOpts.scales.y.ticks, callback: v => Number.isInteger(v) ? v : '' }} }},
        }},
    }},
}});

// Attack vectors pie chart
new Chart(document.getElementById('chartVectors'), {{
    type: 'doughnut',
    data: {{
        labels: VECTOR_LABELS,
        datasets: [{{
            data: VECTOR_VALUES,
            backgroundColor: [
                'rgba(0,63,127,0.8)', 'rgba(0,115,230,0.8)',
                'rgba(0,163,224,0.8)', 'rgba(0,191,255,0.8)',
                'rgba(0,214,198,0.8)', 'rgba(0,230,160,0.8)',
                'rgba(100,140,180,0.8)', 'rgba(50,90,150,0.8)'
            ],
            borderWidth: 2,
            borderColor: '#fff'
        }}]
    }},
    options: {{
        responsive: true,
        plugins: {{
            legend: {{ position: 'right', labels: {{ font: {{ size: 11 }}, padding: 10 }} }},
            tooltip: {{ callbacks: {{ label: ctx => ctx.label + ': ' + ctx.parsed + ' attacks' }} }}
        }}
    }}
}});

// External-detector activation bar chart
new Chart(document.getElementById('chartDetectorActivations'), {{
    type: 'bar',
    data: {{
        labels: DETECTOR_DATES,
        datasets: [{{
            label: '{detector_type} Activations',
            data: DETECTOR_COUNTS,
            backgroundColor: 'rgba(0,115,230,0.78)',
            borderColor: 'rgba(0,115,230,1)',
            borderWidth: 1,
            borderRadius: 5
        }}]
    }},
    options: {{
        responsive: true,
        plugins: {{
            legend: {{ display: false }},
            tooltip: {{ 
                mode: 'index', 
                intersect: false,
                callbacks: {{
                    label: ctx => 'Activations: ' + ctx.parsed.y
                }}
            }}
        }},
        scales: {{
            x: {{ 
                ticks: {{ font: {{ size: 10 }}, maxRotation: 45, minRotation: 45 }}, 
                grid: {{ color: 'rgba(0,0,0,.05)' }} 
            }},
            y: {{ 
                beginAtZero: true, 
                ticks: {{ 
                    font: {{ size: 11 }},
                    callback: v => Number.isInteger(v) ? v : ''
                }}, 
                grid: {{ color: 'rgba(0,0,0,.05)' }},
                title: {{
                    display: true,
                    text: 'Count',
                    font: {{ size: 12 }}
                }}
            }}
        }}
    }}
}});
</script>
</body>
</html>"""

    html_name = f"{detector_type}_Radware_Report_{ts}.html" if detector_type else f"Radware_Attack_Report_{ts}.html"
    
    html_path = output_dir / html_name
    html_path.write_text(html, encoding="utf-8")

    # ── Console summary ────────────────────────────────────────────
    sep = "─" * 70
    print()
    print(sep)
    print(f"  {title}")
    print(sep)
    print(f"  Period           : {period_str}")
    print(f"  {period_label} periods : {num_periods}")
    print(f"  Total events     : {total_events_count}")
    print(f"  Total campaigns  : {total_attacks}")
    print(f"  Peak Bandwidth   : {fmt_bps(global_max_bps)}")
    print(f"  Peak PPS         : {fmt_pps(global_max_pps)}")
    print(f"  Most targeted IP : {most_tgt}  ({most_tgt_count} campaigns)")
    print(sep)
    print(f"  HTML Report: {html_path}")
    print(sep)
    print()

    return html_path


# ══════════════════════════════════════════════════════════════════
#  Configuration and Input Processing
# ══════════════════════════════════════════════════════════════════

def load_config() -> configparser.ConfigParser:
    """Load the report configuration from the script directory."""
    cfg = configparser.ConfigParser(inline_comment_prefixes=(";", "#"), interpolation=None)
    if CONFIG_PATH.exists():
        cfg.read(CONFIG_PATH, encoding="utf-8")
        print(f"[INFO] Loaded config: {CONFIG_PATH}")
    else:
        print(f"[INFO] dfc_security_reporter.ini not found – using built-in defaults.")
    return cfg


def select_detector_type() -> tuple:
    """Interactive menu to select the external detector type."""
    print()
    print("=" * 60)
    print("  SELECT DETECTOR TYPE")
    print("=" * 60)
    print("  [1] Kentik")
    print("  [2] Arbor")
    print("  [3] DefensePro")
    print("=" * 60)
    print()
    
    try:
        choice = input("  Select detector type [1/2/3]: ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\n[INFO] Cancelled by user.")
        sys.exit(0)
    
    if choice not in DETECTOR_TYPES:
        print(f"[ERROR] Invalid selection: '{choice}'. Please choose 1, 2, or 3.")
        sys.exit(1)
    
    return DETECTOR_TYPES[choice]


def select_report_period() -> str:
    """Interactive menu to select weekly or monthly reporting."""
    print()
    print("=" * 60)
    print("  SELECT REPORT PERIOD")
    print("=" * 60)
    print("  [1] Weekly")
    print("  [2] Monthly")
    print("=" * 60)
    print()

    try:
        choice = input("  Select report period [1/2]: ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\n[INFO] Cancelled by user.")
        sys.exit(0)

    if choice not in {"1", "2"}:
        print(f"[ERROR] Invalid selection: '{choice}'. Please choose 1 or 2.")
        sys.exit(1)

    return "weekly" if choice == "1" else "monthly"


def pick_latest_input(input_dir: Path) -> Path:
    """Return the most recently modified .csv or .zip in input_dir."""
    input_dir.mkdir(parents=True, exist_ok=True)
    candidates = list(input_dir.glob('*.csv')) + list(input_dir.glob('*.zip'))
    if not candidates:
        print(f"[ERROR] No .csv or .zip files found in {input_dir}", file=sys.stderr)
        sys.exit(4)
    latest = max(candidates, key=lambda p: p.stat().st_mtime)
    print(f"[INFO] Auto-selected latest input: {latest}")
    return latest


def read_df_from_path(input_path: Path, read_kwargs: dict) -> pd.DataFrame:
    """Read a DataFrame from a .csv file or from the first CSV inside a .zip archive."""
    suffix = input_path.suffix.lower()

    if suffix == '.zip':
        with zipfile.ZipFile(input_path, 'r') as zf:
            csv_names = [n for n in zf.namelist() if n.lower().endswith('.csv')]
            if not csv_names:
                print(f"[ERROR] No CSV file found inside {input_path}", file=sys.stderr)
                sys.exit(4)
            if len(csv_names) > 1:
                print(f"[INFO] Multiple CSVs in zip – using: {csv_names[0]}")
            chosen = csv_names[0]
            print(f"[INFO] Reading '{chosen}' from {input_path.name}")
            with zf.open(chosen) as fh:
                raw = fh.read()
        encoding = read_kwargs.get('encoding', 'utf-8')
        kw = {k: v for k, v in read_kwargs.items() if k != 'encoding'}
        try:
            return pd.read_csv(io.BytesIO(raw), encoding=encoding, **kw)
        except UnicodeDecodeError:
            return pd.read_csv(io.BytesIO(raw), encoding='latin1', **kw)

    # plain CSV
    try:
        return pd.read_csv(input_path, **read_kwargs)
    except UnicodeDecodeError:
        read_kwargs['encoding'] = 'latin1'
        return pd.read_csv(input_path, **read_kwargs)


def pick_report_csv(output_dir: Path) -> Optional[Path]:
    """List existing report CSVs and let the user choose one."""
    csvs = sorted(output_dir.glob("*.csv"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not csvs:
        print(f"[ERROR] No CSV report files found in {output_dir}", file=sys.stderr)
        return None

    print()
    print("  Available report CSVs (newest first):")
    show = csvs[:15]
    for i, p in enumerate(show, 1):
        mtime = datetime.fromtimestamp(p.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
        print(f"  [{i:>2}] {p.name}  ({mtime})")
    if len(csvs) > 15:
        print(f"       ... and {len(csvs) - 15} more")
    print()
    try:
        sel = input(f"  Select file [1-{len(show)}] (default 1 = latest): ").strip()
    except (EOFError, KeyboardInterrupt):
        sel = "1"
    if not sel:
        sel = "1"
    try:
        idx = int(sel) - 1
        if not (0 <= idx < len(show)):
            raise ValueError
    except ValueError:
        print("[WARN] Invalid selection – using latest.", file=sys.stderr)
        idx = 0
    chosen = show[idx]
    print(f"[INFO] Selected: {chosen}")
    return chosen


# ══════════════════════════════════════════════════════════════════
#  Main Entry Point
# ══════════════════════════════════════════════════════════════════

def main():
    cfg = load_config()

    # Command-line argument parser
    def _cfg_val(section: str, key: str, fallback: str) -> str:
        return cfg.get(section, key, fallback=fallback)

    ap = argparse.ArgumentParser(
        description="Radware attack report generator - process CSV and create comprehensive HTML report"
    )
    ap.add_argument("input_csv", nargs='?', default=None,
                    help="Path to input CSV file (optional)")
    ap.add_argument("--mode", choices=["full", "html-only"], default="full",
                    help="Mode: 'full' processes raw CSV, 'html-only' generates HTML from existing report")
    ap.add_argument("--detector-type", choices=["kentik", "arbor", "defensepro"], default=None,
                    help="Detector type: kentik, arbor, or defensepro (prompts if not specified)")
    ap.add_argument("--report-period", choices=["weekly", "monthly"], default=None,
                    help="Report period: weekly or monthly (prompts if not specified)")
    ap.add_argument("--input-dir", default=None,
                    help="Directory containing input CSV files (defaults to the Forensics input directory)")
    ap.add_argument("--output-dir", default=None,
                    help="Directory to save output reports (defaults to Reports)")
    ap.add_argument("--report-csv", default=None,
                    help="Existing report CSV to use for HTML generation (html-only mode)")
    ap.add_argument("--gap-min", type=int, default=None,
                    help="Time gap in minutes to group attacks into campaigns")
    ap.add_argument("--time-format", default=None,
                    help="Input datetime format")
    ap.add_argument("--split-by-port", action="store_true",
                    help="Split campaigns by destination port")
    ap.add_argument("--bps-unit", choices=["auto", "Gbps", "Mbps", "Kbps", "bps"], default=None,
                    help="Bandwidth display unit")
    ap.add_argument("--pps-unit", choices=["auto", "Mpps", "Kpps", "pps"], default=None,
                    help="Packet rate display unit")
    ap.add_argument("--title", default=None,
                    help="Report title")
    ap.add_argument("--start-time", default=None,
                    help="Filter start time (YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)")
    ap.add_argument("--end-time", default=None,
                    help="Filter end time (YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)")
    ap.add_argument("--last-hours", type=float, default=None,
                    help="Filter to last N hours")
    ap.add_argument("--last-days", type=float, default=None,
                    help="Filter to last N days")
    ap.add_argument("--non-interactive", action="store_true",
                    help="Run in non-interactive mode (requires --detector-type)")

    args = ap.parse_args()

    # ── Interactive selection if not specified ────────────────────
    if not args.non_interactive:
        if not args.detector_type:
            detector_type_id, detector_type_name = select_detector_type()
            args.detector_type = detector_type_id
        else:
            detector_type_name = args.detector_type.capitalize()
        if not args.report_period:
            args.report_period = select_report_period()
    else:
        if not args.detector_type:
            print("[ERROR] --non-interactive mode requires --detector-type", file=sys.stderr)
            sys.exit(1)
        detector_type_name = args.detector_type.capitalize()
        if not args.report_period:
            print("[ERROR] --non-interactive mode requires --report-period", file=sys.stderr)
            sys.exit(1)

    print()
    print(f"[INFO] Detector Type: {detector_type_name}")
    print()

    # ── Determine paths from the shared input tree ─────────────────
    if args.input_dir:
        input_dir = Path(args.input_dir)
        if not input_dir.is_absolute():
            input_dir = SCRIPT_DIR / input_dir
    else:
        input_dir = SCRIPT_DIR / _cfg_val("paths", "forensics_input", "Inputs/Forensics Input")
    
    # Output directory - always use the main Reports folder
    if args.output_dir:
        output_dir = Path(args.output_dir)
    else:
        output_base = _cfg_val("paths", "output_dir", "Reports")
        output_dir = SCRIPT_DIR / output_base
    
    output_dir.mkdir(parents=True, exist_ok=True)

    activation_string = _cfg_val(
        f"detector:{args.detector_type}",
        "activation_str",
        ""
    )

    # DefenseFlow enrichment is shared by both external detector types.
    defenseflow_dir = SCRIPT_DIR / _cfg_val("paths", "defenseflow_input", "Inputs/DefenseFlow Input")
    log_source = []
    
    if defenseflow_dir.exists():
        log_source = find_dfc_support_sources(defenseflow_dir)
        if log_source:
            print(f"[INFO] Using {len(log_source)} DefenseFlow source(s): {log_source[0].name} ...")
        else:
            print(f"[INFO] No dfc_support folder/ZIP found in {defenseflow_dir}, detector enrichment will be omitted")
    else:
        print(f"[INFO] DefenseFlow input directory not found at {defenseflow_dir}, detector enrichment will be omitted")

    # ── Mode configuration ─────────────────────────────────────────
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if args.title:
        report_title = args.title
    else:
        title_template = _cfg_val("report", "title_template", "{detector_type} Radware Attack Report")
        report_title = title_template.format(
            detector_type=detector_type_name,
            period=f"{args.report_period.capitalize()} Analysis"
        )

    # ── HTML-only mode ─────────────────────────────────────────────
    if args.mode == "html-only":
        # Read time filter for DefenseFlow activation filtering.
        start_time, end_time = read_time_filter_from_config(cfg)
        
        if args.report_csv:
            report_path = Path(args.report_csv)
        else:
            report_path = pick_report_csv(output_dir)
        
        if report_path is None or not report_path.exists():
            print("[ERROR] No valid report CSV found.", file=sys.stderr)
            sys.exit(1)

        print(f"[INFO] Loading existing report: {report_path}")
        try:
            campaign_df = pd.read_csv(report_path, encoding="utf-8")
        except UnicodeDecodeError:
            campaign_df = pd.read_csv(report_path, encoding="latin1")
        except Exception as ex:
            print(f"[ERROR] Failed reading {report_path}: {ex}", file=sys.stderr)
            sys.exit(1)

        # Normalize columns
        campaign_df.columns = [c.strip() for c in campaign_df.columns]
        for col in ("Attack Window Start", "Attack Window End"):
            if col in campaign_df.columns:
                campaign_df[col] = pd.to_datetime(campaign_df[col], errors="coerce")
        for col in ("Peak pps", "Peak bps", "Duration (mins)"):
            if col in campaign_df.columns:
                campaign_df[col] = pd.to_numeric(campaign_df[col], errors="coerce")

        html_path = generate_html_report(
            campaign_df, output_dir, ts, report_title,
            detector_type=detector_type_name,
            activation_string=activation_string,
            report_period=args.report_period,
            log_dir=log_source,
            start_time=start_time, end_time=end_time,
            total_events=None,
            raw_events_df=None
        )
        if html_path:
            print(f"[SUCCESS] HTML report generated: {html_path}")
        return

    # ── Full mode: Process raw CSV ────────────────────────────────
    if args.input_csv:
        input_path = Path(args.input_csv)
        if not input_path.is_absolute():
            input_path = input_dir / input_path.name
    else:
        input_path = pick_latest_input(input_dir)

    if not input_path.exists():
        print(f"[ERROR] Input file not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    print(f"[INFO] Input directory: {input_dir}")
    print(f"[INFO] Processing input: {input_path}")
    print(f"[INFO] Output directory: {output_dir}")

    # ── Apply configuration with CLI overrides ─────────────────────
    gap_min = args.gap_min if args.gap_min is not None else int(_cfg_val("processing", "gap_min", "5"))
    time_format = args.time_format or _cfg_val("processing", "time_format", "%m.%d.%Y %H:%M:%S")
    encoding = _cfg_val("processing", "encoding", "utf-8")
    
    global _BPS_UNIT, _PPS_UNIT
    _BPS_UNIT = args.bps_unit or _cfg_val("units", "bps_unit", "auto")
    _PPS_UNIT = args.pps_unit or _cfg_val("units", "pps_unit", "auto")

    # Read input CSV
    read_kwargs = {
        'engine': 'python',
        'encoding': encoding,
    }

    try:
        df = read_df_from_path(input_path, read_kwargs)
    except Exception as ex:
        print(f"[ERROR] Failed reading input: {ex}", file=sys.stderr)
        sys.exit(1)

    df.columns = [c.strip() for c in df.columns]
    print(f"[INFO] Loaded {len(df)} rows")
    source_event_count = len(df)

    # Resolve column mappings
    try:
        cols = resolve_columns(df)
    except ValueError as ex:
        print(f"[ERROR] {ex}", file=sys.stderr)
        sys.exit(2)

    # ── Save unfiltered data for event counting ───────────────────
    # Keep a copy before filtering invalid IPs for accurate event counts
    df_all_events = df.copy()

    # ── Filter out invalid destination IPs ────────────────────────
    dst_ip_col = cols["Destination IP Address"]
    initial_rows = len(df)
    
    # Remove rows with 0.0.0.0 or "Multiple" as destination IP
    invalid_ips = ["0.0.0.0", "Multiple", "multiple", "MULTIPLE"]
    mask = ~df[dst_ip_col].astype(str).str.strip().isin(invalid_ips)
    df = df[mask].reset_index(drop=True)
    
    filtered_count = initial_rows - len(df)
    if filtered_count > 0:
        print(f"[INFO] Filtered out {filtered_count} rows with invalid Destination IP (0.0.0.0 or Multiple) for campaign grouping")
        print(f"[INFO] Remaining rows for campaigns: {len(df)}")
        print(f"[INFO] Total events (including filtered): {len(df_all_events)}")
    
    if df.empty:
        print("[WARN] No data remains after filtering invalid IPs – nothing to process.")
        sys.exit(0)

    # Parse datetime columns
    try:
        df[cols['Start Time']] = parse_datetime_col(df[cols['Start Time']], time_format)
        df[cols['End Time']] = parse_datetime_col(df[cols['End Time']], time_format)
        # Also parse datetime for unfiltered events
        df_all_events[cols['Start Time']] = parse_datetime_col(df_all_events[cols['Start Time']], time_format)
        df_all_events[cols['End Time']] = parse_datetime_col(df_all_events[cols['End Time']], time_format)
    except Exception as ex:
        print(f"[ERROR] Failed parsing datetimes: {ex}", file=sys.stderr)
        sys.exit(3)

    # Convert numeric columns
    for num_col_key in ["Total Packets Dropped", "Total Mbits Dropped", "Max pps", "Max bps"]:
        if num_col_key in cols:
            df[cols[num_col_key]] = pd.to_numeric(df[cols[num_col_key]], errors='coerce')
            df_all_events[cols[num_col_key]] = pd.to_numeric(df_all_events[cols[num_col_key]], errors='coerce')

    # ── Apply time filter ──────────────────────────────────────────
    start_time = None
    end_time = None
    
    # Command-line arguments take precedence
    if args.last_hours:
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=args.last_hours)
    elif args.last_days:
        end_time = datetime.now()
        start_time = end_time - timedelta(days=args.last_days)
    elif args.start_time or args.end_time:
        if args.start_time:
            try:
                start_time = pd.to_datetime(args.start_time)
            except Exception:
                print(f"[WARN] Could not parse --start-time: {args.start_time}")
        if args.end_time:
            try:
                end_time = pd.to_datetime(args.end_time)
            except Exception:
                print(f"[WARN] Could not parse --end-time: {args.end_time}")
    else:
        # Fall back to config file
        start_time, end_time = read_time_filter_from_config(cfg)
    
    # Apply the filter to both datasets
    if start_time or end_time:
        df = apply_time_filter(df, cols, start_time, end_time)
        df_all_events = apply_time_filter(df_all_events, cols, start_time, end_time)
        if df.empty:
            print("[WARN] No data remains after time filter – nothing to process.")
            sys.exit(0)

    # Group campaigns
    print(f"[INFO] Grouping campaigns with gap={gap_min} minutes...")
    campaign_df = group_campaigns_by_dst(
        df, cols,
        gap_minutes=gap_min,
        split_by_port=args.split_by_port
    )
    print(f"[INFO] Created {len(campaign_df)} campaigns")

    # Save campaign CSV
    csv_name = f"{detector_type_name}_Radware_Campaigns_{ts}.csv"
    csv_path = output_dir / csv_name
    campaign_df.to_csv(csv_path, index=False, encoding="utf-8")
    print(f"[INFO] Campaign CSV saved: {csv_path}")

    # Prepare raw events dataframe with standardized column names for report
    raw_events_for_report = df_all_events.copy()
    raw_events_for_report = raw_events_for_report.rename(columns={
        cols["Start Time"]: "Attack Window Start",
        cols["Destination IP Address"]: "Destination IP"
    })

    # Generate HTML report (pass raw events for accurate event counts)
    html_path = generate_html_report(
        campaign_df, output_dir, ts, report_title,
        detector_type=detector_type_name,
        activation_string=activation_string,
        report_period=args.report_period,
        log_dir=log_source,
        start_time=start_time, end_time=end_time,
        total_events=source_event_count,
        raw_events_df=raw_events_for_report
    )
    if html_path:
        print(f"[SUCCESS] HTML report generated: {html_path}")


if __name__ == "__main__":
    main()
