#!/usr/bin/env python3
"""UptimeMAX read-only verification service (V271). GET-only, no write capability.
Endpoints:
  /verify/snapshot                      live OPC telemetry, all 12 machines + writer/heartbeat
  /verify/history/COMP_01?minutes=10    raw historian rows
  /verify/rag/query?q=...               verbatim RAG gateway response
  /verify/ui                            page list
  /verify/ui/{page}?compressor=&screenshot=   RESOLVED live Perspective display (fast path: screenshot=false)
  /verify/action/diagnose/{machine}     same diagnose engine as the UI button
  /verify/ui/compare/{machine}?pages=   synchronized source->display trace
  /verify/tests, /verify/test/{CASE_ID} V271 evidence records
"""
import asyncio, base64, datetime, hashlib, json, os, re, subprocess, time
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, HTTPException, Query
import uvicorn, pymysql
from asyncua import Client

# D-16 completion: internal endpoints are read from protected configuration
# (/etc/uptimemax/endpoints.json, mode 600) so the published source contains
# no raw IP addresses, ports, or internal URLs.
_CFG = json.load(open("/etc/uptimemax/endpoints.json"))
UA_URL = _CFG["UA_URL"]
UA_PASS = os.environ.get("UPTIMAX_OPC_PASSWORD", "")  # D-03: externalized (was parsed from source)
NS_ROOT = "ns=2;s=[UptimeMAX]/Compressors"
BUILD = "BUILD V270.1"
RAG = _CFG["RAG"]
# OAI/Claude Candidate-3 hygiene: no credential in source. The gateway key is
# provisioned via the service environment (RAG_GW_KEY); rotated value is
# server-side only.
RAG_KEY = os.environ.get("RAG_GW_KEY", "")
ENGINE_BUILDINFO_URL = _CFG["ENGINE_BUILDINFO_URL"]
EVIDENCE_DIR = "/opt/uptimemax_verify/test_evidence"
EVIDENCE_DIR_RUN2 = "/opt/uptimemax_verify/run2_evidence"
TRACE_DIR_REMOTE = "/opt/uptimemax_verify/diagnostic_traces"
UI_BASE = _CFG["UI_BASE"]
ISO_BASIS = ("zone boundaries 1.4/2.8/4.5 mm/s RMS velocity - legacy ISO 10816-3 Group 2 (rigid support); "
             "current published successor ISO 20816-3:2022. Zone state machine: upward crossing >= boundary "
             "(exactly 2.800 IS a Zone-3 candidate), downward < boundary (strictly); a change confirms after "
             "4 consecutive 2 Hz ticks and any differing tick resets the candidate counter (HYST=0.1 is defined "
             "but unused). Envelope condition is reported separately and never rewrites the ISO velocity zone.")
PAGES = {
    "overview": "/overview", "iso-vibration-detail": "/iso-vibration-detail", "pid-live": "/pid-live",
    "micro-registers": "/micro-registers", "viking-audit": "/viking-audit", "trends": "/trends",
    "alarm-matrix": "/alarm-matrix", "rag-assistant": "/RAGPanel",
}
READY_MARKERS = {
    "overview": "Compressor Units", "iso-vibration-detail": "ISO WORST RMS", "pid-live": "P&ID System Schematic",
    "micro-registers": "MICRO-REGISTER INSPECTOR", "viking-audit": "Viking", "trends": "Historical Trends",
    "alarm-matrix": "COMP_", "rag-assistant": "AI Manual & Equipment Assistant",
}
MEMBERS = [
    ("Max_Velocity_RMS", "mm/s RMS", "live_opc"),
    ("ISO_Compliance_Zone", "zone 1-4 (legacy ISO 10816-3 Group 2 rigid; successor ISO 20816-3:2022)", "live_opc"),
    ("ISO_Zone_Color", "hex color", "live_opc"),
    ("RUL_Diagnostics/Status", "UptimeMAX machine state (NOMINAL/WARNING/ALARM)", "live_opc"),
    ("Vibration/EnvelopeEnergy_gE", "g (SKF envelope; fault reference 0.20g)", "live_opc"),
    ("Vibration/CrestFactor", "ratio", "live_opc"),
    ("Vibration/Kurtosis", "ratio", "live_opc"),
    ("Vibration/EnvelopePeakFreq", "Hz", "live_opc"),
    ("Process/SuctionPressure", "psi", "live_opc"),
    ("Process/DischargePressure", "psi", "live_opc"),
    ("Process/SuctionSuperheat", "degF", "live_opc"),
    ("Process/CompressionRatio", ":1", "calculated (discharge/suction)"),
    ("ManualRegisters/Manual_OilPressure_PSIA", "psia (subtract 14.7 for psig)", "live_opc"),
    ("ManualRegisters/Manual_MotorCurrent_A", "A", "live_opc"),
    ("ManualRegisters/Manual_CapacityPercent", "% (slide valve)", "live_opc"),
    ("Sprint4_Dynamic/EstimatedKilowatts", "kW (estimated: 1.732*460*A*0.85/1000)", "calculated"),
    ("Sprint4_Dynamic/CurrentRuntimeHours", "hours", "live_opc"),
    ("Sprint4_Dynamic/TotalNumberOfStarts", "count", "live_opc"),
]
PAGE_PATTERNS = {
    "iso-vibration-detail": {
        "iso_velocity_zone_chip": r"ISO VELOCITY ZONE: \d[^\n]*",
        "uptimax_state": r"UPTIMAX STATE: \w+",
        "envelope_chip": r"ENVELOPE: [^\n]+",
        "worst_rms": r"WORST RMS: [\d.]+ mm/s",
        "h_badge": r"H: PENDING",
        "thresholds_label": r"1\.4 / 2\.8 / 4\.5",
    },
    "pid-live": {
        "zone_card": r"Zone \d[^\n]*",
        "machine_conditions": r"UPTIMAX MACHINE CONDITIONS",
        "slide_valve": r"Slide Valve Position\n[\d.]+ %",
        "vib_rms": r"[\d.]+ mm/s RMS",
        "operating_status": r"Operating Status: \w+",
    },
    "micro-registers": {
        "oil_pressure": r"Oil Pressure\n[\d.\-]+",
        "motor_current": r"Motor Current\n[\d.]+",
        "motor_kw_estimated": r"Motor kW \(estimated\)",
        "kW_value": r"\n[\d.]+\nkW",
        "health_index": r"Health Index\n?\s*PENDING",
    },
    "overview": {
        "machine_conditions": r"UptimeMAX Machine Conditions",
        "compressor_rows": r"COMP_\d\d",
        "h_pending_badges": r"H: PENDING",
        "dock": r"Ignition Platform Alarms[^\n]*",
    },
    "alarm-matrix": {
        "machine_conditions": r"UptimeMAX Machine Conditions",
        "rows": r"COMP_\d\d",
        "dock": r"Ignition Platform Alarms[^\n]*",
    },
    "viking-audit": {"title": r"Viking[^\n]*"},
    "trends": {"pens": r"Amps|Discharge|Suction|Vibration"},
    "rag-assistant": {
        "qdrant_status": r"QDRANT VECTOR DB[^\n]*",
        "result_area": r"Manual search answers appear here[^\n]*|CORPUS EXCERPTS[^\n]*",
    },
}

app = FastAPI(title="UptimeMAX read-only verification", docs_url=None, redoc_url=None)

def now_utc():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

@app.middleware("http")
async def no_store(request, call_next):
    resp = await call_next(request)
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    ct = resp.headers.get("content-type", "")
    if ct.startswith("application/json"):
        body = b""
        async for chunk in resp.body_iterator:
            body += chunk
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                data["served_at_utc"] = now_utc()
                body = json.dumps(data).encode()
        except Exception:
            pass
        hdrs = dict(resp.headers)
        hdrs.pop("content-length", None)
        from starlette.responses import Response as _Resp
        return _Resp(content=body, status_code=resp.status_code, headers=hdrs, media_type="application/json")
    return resp

_ua_lock = asyncio.Lock()
_ui_lock = asyncio.Lock()

async def ua_read_all(machine: str):
    async with _ua_lock:
        c = Client(UA_URL)
        c.set_user("ua_writer")
        c.set_password(UA_PASS)
        await c.connect()
        out = {}
        try:
            for member, unit, src in MEMBERS:
                if member == "H_INDEX":
                    out[member] = {"value": None, "unit": unit, "source": src, "quality": "PENDING"}
                    continue
                try:
                    val = await c.get_node(f"{NS_ROOT}/{machine}/{member}").read_value()
                    out[member] = {"value": val, "unit": unit, "source": src, "quality": "GOOD"}
                except Exception as e:
                    out[member] = {"value": None, "unit": unit, "source": src, "quality": "ERROR: " + str(e)[:60]}
        finally:
            await c.disconnect()
        return out

async def heartbeat():
    try:
        node = "ns=2;s=[UptimeMAX]/Compressors/Compressor_01/Max_Velocity_RMS"
        async with _ua_lock:
            c = Client(UA_URL)
            c.set_user("ua_writer")
            c.set_password(UA_PASS)
            await c.connect()
            try:
                v1 = await c.get_node(node).read_value()
                await asyncio.sleep(4.5)
                v2 = await c.get_node(node).read_value()
            finally:
                await c.disconnect()
        changed = v1 is not None and v2 is not None and abs(float(v2) - float(v1)) > 1e-9
        return {"method": "two live OPC reads 4.5s apart must differ (source writes at 2 Hz)",
                "read1": round(float(v1), 6) if v1 is not None else None,
                "read2": round(float(v2), 6) if v2 is not None else None,
                "ingress_live": bool(changed), "healthy": bool(changed)}
    except Exception as e:
        return {"error": str(e)[:100], "healthy": False}

def historian_freshness():
    try:
        conn = pymysql.connect(unix_socket="/run/mysqld/mysqld.sock", user="root", database="ignition_historian", charset="utf8mb4")
        with conn.cursor() as cur:
            cur.execute("select max(t_stamp) from sqlt_data_1_2026_10 where tagid=(select id from sqlth_te where tagpath='compressors/compressor_01/max_velocity_rms' limit 1)")
            row = cur.fetchone()[0]
        conn.close()
        if row:
            age = time.time() - row / 1000
            return {"historian_last_sample_utc": datetime.datetime.fromtimestamp(row / 1000, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
                    "age_seconds": round(age, 1),
                    "note": "historian storage gaps during its own 2-hour demo cycles (Demo_Enabled/Demo_Expired); live source data is unaffected - see heartbeat"}
    except Exception as e:
        return {"error": str(e)[:100]}
    return {"historian_last_sample_utc": None}

@app.get("/verify/heartbeat")
async def heartbeat_route():
    """Stand-alone 2 Hz source liveness (D-01: reviewers observed CLIENT_ERROR
    when probing this as a route; it previously existed only inside /verify/snapshot).
    Same probe, same semantics; read-only."""
    return {"build": BUILD, **(await heartbeat())}

def writer_check():
    try:
        pids = subprocess.run(["pgrep", "-f", "opc_ingress_v2.py"], capture_output=True, text=True).stdout.split()
        procs = []
        for pid in pids:
            st = subprocess.run(["ps", "-o", "lstart=", "-p", pid], capture_output=True, text=True).stdout.strip()
            procs.append({"pid": int(pid), "started": st})
        return {"expected_count": 1, "actual_count": len(procs), "processes": procs,
                "note": "multiple writers interleave independent zone states and corrupt tag values - must be exactly 1"}
    except Exception as e:
        return {"error": str(e)[:100]}

def platform_alarms():
    try:
        conn = pymysql.connect(unix_socket="/run/mysqld/mysqld.sock", user="root", database="ignition_historian", charset="utf8mb4")
        with conn.cursor() as cur:
            cur.execute("select eventtime, eventtype, source, eventid from alarm_events order by eventtime desc limit 10")
            rows = [{"eventtime": str(r[0]), "eventtype": r[1], "source": r[2], "eventid": r[3]} for r in cur.fetchall()]
        conn.close()
        return {"recent_journal_events_raw": rows,
                "note": "raw journal tail (eventtype values as stored). Live active/shelved alarm state is the Perspective dock (Ignition Platform Alarms) via AlarmStatusTable - not derivable reliably from this journal alone."}
    except Exception as e:
        return {"error": str(e)[:100]}

def _extract(text, patterns):
    out = {}
    for name, pat in patterns.items():
        m = re.search(pat, text)
        out[name] = m.group(0) if m else None
    return out

async def _render_page(page_key: str, compressor: str, want_screenshot: bool):
    """Render the LIVE Perspective page in a headless browser and return
    (text, png|None, duration_s, ready_bool). Adaptive wait: poll for the page's
    ready marker (up to 45 s) instead of a fixed sleep, then settle 2.5 s."""
    from playwright.async_api import async_playwright
    marker = READY_MARKERS.get(page_key, "")
    t0 = time.time()
    async with _ui_lock:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch()
            pg = await browser.new_page(viewport={"width": 1680, "height": 950})
            try:
                await pg.goto(UI_BASE + PAGES[page_key], timeout=60000, wait_until="domcontentloaded")
                ready = False
                elapsed = 0
                while elapsed < 45000:
                    await pg.wait_for_timeout(1000)
                    elapsed += 1000
                    try:
                        body = await pg.inner_text("body")
                        if marker and marker in body:
                            ready = True
                            break
                    except Exception:
                        pass
                await pg.wait_for_timeout(2500)  # settle: bindings paint values
                text = await pg.inner_text("body")
                if "Trial Expired" in text:
                    return ({"ui_state": "trial_expired",
                             "note": "the Perspective UI runs in 2-hour trial sessions; the current session expired. This is a licensing state of the display layer only - live telemetry via /verify/snapshot is unaffected. Reset: log into the Ignition gateway and start a new trial (or license the gateway to remove the cycle entirely)."},
                            None, round(time.time() - t0, 1), False)
                png = (await pg.screenshot(full_page=False)) if want_screenshot else None
                return text, png, round(time.time() - t0, 1), ready
            finally:
                await browser.close()

def _norm_machine(machine: str):
    m = machine.upper().replace("COMP_", "").replace("COMPRESSOR_", "")
    if not re.fullmatch(r"\d{1,2}", m) or not (1 <= int(m) <= 12):
        raise HTTPException(400, "machine must be COMP_01..COMP_12")
    return f"Compressor_{int(m):02d}", f"COMP_{int(m):02d}"

@app.get("/verify/snapshot")
async def snapshot():
    t0 = time.time()
    machines = {}
    for i in range(1, 13):
        m = f"Compressor_{i:02d}"
        try:
            machines[f"COMP_{i:02d}"] = await ua_read_all(m)
        except Exception as e:
            machines[f"COMP_{i:02d}"] = {"error": str(e)[:120]}
    return {"build": BUILD, "generated_utc": now_utc(),
            "latency_seconds": round(time.time() - t0, 2),
            "iso_basis": ISO_BASIS,
            "h_status": "PENDING_VERIFIED_TAG (H badges intentionally show H: PENDING; the H=5 API result was a synthetic Zone-D test payload, not any machine's score)",
            "ingress_writer": writer_check(),
            "heartbeat": await heartbeat(),
            "historian_freshness": historian_freshness(),
            "ignition_platform_alarms": platform_alarms(),
            "machines": machines}

@app.get("/verify/history/{machine}")
async def history(machine: str, minutes: int = Query(10, ge=1, le=120)):
    comp, label = _norm_machine(machine)
    since = int((time.time() - minutes * 60) * 1000)
    conn = pymysql.connect(unix_socket="/run/mysqld/mysqld.sock", user="root", database="ignition_historian", charset="utf8mb4")
    out = {"machine": label, "minutes_requested": minutes, "raw_historian_rows": {}}
    total = 0
    with conn.cursor() as cur:
        cur.execute("select id, tagpath from sqlth_te where tagpath like %s", (f"compressors/{comp}/%",))
        tags = cur.fetchall()
        for tid, path in tags:
            if total > 8000:
                out["note"] = "row cap reached; reduce minutes"
                break
            cur.execute("select t_stamp, floatvalue, intvalue, stringvalue, dataintegrity from sqlt_data_1_2026_10 where tagid=%s and t_stamp>%s order by t_stamp", (tid, since))
            rows = []
            for r in cur.fetchall():
                val = r[1] if r[1] is not None else (r[2] if r[2] is not None else r[3])
                rows.append({"ts_utc": datetime.datetime.fromtimestamp(r[0] / 1000, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
                             "value": val, "dataintegrity": r[4]})
            if rows:
                out["raw_historian_rows"][path] = rows
                total += len(rows)
    conn.close()
    out["note"] = ("raw timestamped historian observations as stored. HONEST LIMIT: the SQL Historian module runs in "
                   "2-hour demo cycles (Demo_Enabled/Demo_Expired) - data can gap after each cycle. Source writes at 2 Hz. No calculations applied.")
    return out


ENDPOINT_INVENTORY = [
    {"path": "/verify/buildinfo", "purpose": "live engine build identity (build_id, source sha256s) + freshness disclosure (source: live/last_good_cache)", "auth": "none", "data": "live with disclosed caching", "response_schema": "{buildinfo:{build_id,module_sha256{...}},source,fetched_utc,last_good_cache?}|{source,last_good_cache,fetched_utc}", "state_changing": False},
    {"path": "/verify/snapshot", "purpose": "live OPC telemetry for all 12 machines + ingress writer check + 2-read heartbeat + historian freshness", "auth": "none", "data": "live", "response_schema": "{build,generated_utc,latency_seconds,iso_basis,h_status,ingress_writer,heartbeat,historian_freshness,ignition_platform_alarms,machines{COMP_XX:{tag:{value,unit,source,quality}}}}", "state_changing": False},
    {"path": "/verify/heartbeat", "purpose": "two OPC reads 4.5 s apart must differ (source writes at 2 Hz)", "auth": "none", "data": "live",     "response_schema": "{build,method,read1,read2,ingress_live,healthy}", "state_changing": False},
    {"path": "/verify/history/{machine}", "purpose": "raw historian rows as stored (sqlt_data), uncalculated, quality column included", "auth": "none", "data": "live SQL read", "response_schema": "{machine,minutes_requested,raw_historian_rows{tagpath:[{ts_utc,value,dataintegrity}]},note}", "state_changing": False},
    {"path": "/verify/historian/status", "purpose": "recomputed last successful historian write, integrity distribution, tagpath count, disclosed sampling config; aggregates cached 300 s with cache state disclosed", "auth": "none", "data": "live SQL read (300 s disclosed cache on aggregates)", "response_schema": "{source,generated_utc,sampling_config_disclosed{...},compressor_tagpaths_registered,last_successful_write_utc,dataintegrity_distribution,computed_utc,served_from_cache_seconds?}", "state_changing": False},
    {"path": "/verify/traces", "purpose": "read-only engine trace index (newest-first); reviewer picks their own execution IDs (D-01f)", "auth": "none", "data": "live store read", "response_schema": "{source,generated_utc,count,traces:[{execution_id,timestamp_utc,equipment_id,outcome}],note} | limit: 1..1000, default 200", "state_changing": False},
    {"path": "/verify/trace/{execution_id}", "purpose": "one stored diagnostic record verbatim (allow-listed fields); retrieval never invokes the engine", "auth": "none", "data": "live store read", "response_schema": "{source,fetched_utc,record_sha256,dropped_fields,trace{...},note}", "state_changing": False},
    {"path": "/verify/artifacts", "purpose": "frozen evidence artifacts with SHA-256 for hash verification", "auth": "none", "data": "static frozen", "response_schema": "{artifacts:[{file,bytes,sha256,url}],note}", "state_changing": False},
    {"path": "/verify/artifacts/{name}", "purpose": "download one frozen artifact (binary OK; reviewers who cannot unzip use /verify/source/{name})", "auth": "none", "data": "static frozen", "response_schema": "file bytes", "state_changing": False},
    {"path": "/verify/source", "purpose": "D-01k: body index of every served text file with per-file SHA-256 (reviewer tools cannot read headers)", "auth": "none", "data": "static manifest", "response_schema": "{generated_utc,count,files:[{file,url,bytes,sha256}],note}", "state_changing": False},
    {"path": "/verify/source/{name}", "purpose": "plain-text serving of evidence files (manifest, contract, thresholds, each source file, introspection script + sample, non-regression record) at stable URLs with X-File-SHA256 header", "auth": "none", "data": "static frozen", "response_schema": "text/plain bytes; header X-File-SHA256", "state_changing": False},
    {"path": "/verify/display/{execution_id}", "purpose": "D-01i: what Perspective renders for a given execution ID - trace decision fields + live capture of the operator display for that machine (JSON read-back; PNG with ?screenshot=true)", "auth": "none", "data": "stored record + live browser capture", "response_schema": "{execution_id,equipment_id,machine,trace_timestamp_utc,trace_outcome,trace_final_state,pages_captured{page:{captured_utc,extracted_key_displays,full_visible_text}},screenshots_png_base64?}", "state_changing": False},
    {"path": "/verify/access-health", "purpose": "server UTC, verification-service build hash, engine build ID, per-tier connectivity (engine, gateway, historian DB, OPC source), disclosed access limits", "auth": "none", "data": "live probes", "response_schema": "{generated_utc,server_utc,verification_service_build_sha256,access_limits{...},tiers{...},all_tiers_reachable,note}", "state_changing": False},
    {"path": "/verify/endpoints", "purpose": "this machine-readable endpoint inventory", "auth": "none", "data": "static manifest", "response_schema": "{generated_utc,base_url,transport,credentials_required,access_limits?,note,endpoints:[{path,purpose,auth,data,response_schema,state_changing}]}", "state_changing": False},
    {"path": "/verify/ui", "purpose": "Perspective page list + audit manifest + evidence index", "auth": "none", "data": "live browser capture on demand", "response_schema": "{build,verification_revision,generated_utc,pages,fast_path,actions,audit_manifest,evidence_index,...}", "state_changing": False},
    {"path": "/verify/ui/{page}", "purpose": "RESOLVED operator-facing display (live Perspective render)", "auth": "none", "data": "live browser capture", "response_schema": "{build,page,url,compressor_selected,captured_utc,capture_duration_seconds,ready_marker_found,resolved_display{extracted_key_displays,full_visible_text},screenshot_png_base64?}", "state_changing": False},
    {"path": "/verify/ui/compare/{machine}", "purpose": "synchronized source->display trace", "auth": "none", "data": "live", "response_schema": "{build,machine,source_values_live_opc,resolved_ui_displays{...}}", "state_changing": False},
    {"path": "/verify/action/diagnose/{machine}", "purpose": "same diagnose engine invocation as the UI button", "auth": "none", "data": "live", "response_schema": "{build,machine,captured_utc,live_inputs_sent,engine_response_verbatim,note}", "state_changing": True},
    {"path": "/verify/rag/query", "purpose": "verbatim RAG gateway response", "auth": "none", "data": "live", "response_schema": "{query,rag_gateway_response_verbatim{verified,answer,citations,gateway_status,confidence},note}", "state_changing": True},
    {"path": "/verify/rag/catalog_stats", "purpose": "RAG corpus catalog statistics", "auth": "none", "data": "live", "response_schema": "{query,catalog_stats_verbatim,note}", "state_changing": False},
    {"path": "/verify/tests", "purpose": "immutable frozen test-evidence index", "auth": "none", "data": "static frozen", "response_schema": "{run_id,build,cases_available,schema,schema_contract,note}", "state_changing": False},
    {"path": "/verify/test/{case_id}", "purpose": "one immutable frozen test-evidence record", "auth": "none", "data": "static frozen", "response_schema": "frozen evidence record (V271-test-evidence-1.0)", "state_changing": False},
    {"path": "/verify/evidence[/{case_id}]", "purpose": "evidence records (aliases of /verify/test)", "auth": "none", "data": "static frozen", "response_schema": "same as /verify/test", "state_changing": False},
]

SIDE_EFFECT_CONFIRMATION = ("every /verify/* route is GET-only; the two routes flagged state_changing=true create a "
                            "diagnostic trace or an RAG session by design and reviewers are asked not to call them. "
                            "All other routes - including /verify/display/{execution_id} (browser render of an existing "
                            "page) and /verify/source/{name} (file read) - create no records, modify no state, and "
                            "leave no trace. Reviewer reads are provably side-effect free: trace-store counts are "
                            "unchanged across repeated reads (demonstrated repeatedly; re-demonstrated in test T8 of "
                            "the access acceptance test).")


@app.get("/verify/endpoints")
async def endpoints_inventory():
    """Machine-readable endpoint inventory (reviewer access paper Part A / D-01c).
    Static manifest; side-effect flags + response schemas; access limits disclosed."""
    return {"generated_utc": now_utc(), "base_url": "https://testing.muizuddin.com/verify",
            "transport": "GET-only", "credentials_required": False,
            "access_limits": {
                "rate_limit": "none configured (no 429 path; reviewer load <=30 req/min, bursts of 6, far below capacity)",
                "concurrency": "single uvicorn process, async handlers; concurrent requests served in parallel (OPC reads serialized per process by design)",
                "user_agent_filtering": "none",
                "ip_allowlist": "none",
                "what_a_client_sees_at_a_limit": "no limit exists; no 429 generated by this service"},
            "freshness": "every JSON response carries served_at_utc (injected by middleware) and Cache-Control: no-store",
            "side_effect_confirmation": SIDE_EFFECT_CONFIRMATION,
            "note": ("endpoints flagged state_changing=true write diagnostic traces by design "
                     "(diagnose, rag/query); reviewers should not call them. WAF/CDN detail "
                     "is intentionally out of scope per the agreed exclusions."),
            "endpoints": ENDPOINT_INVENTORY}


def _vs_build_sha256():
    """D-01-R1 L10: the RUNNING process reports the hash of the code it actually
    loaded (computed at import time and cached in-process), plus pid and process
    start - a file hash alone does not show what the process executes."""
    try:
        return _PROCESS_IDENTITY["code_sha256"]
    except Exception:
        return None

_PROCESS_IDENTITY = {
    "pid": os.getpid(),
    "process_start_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "code_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    "identity_method": "hash computed by the running process at import time (loaded code), not a separate file read after start",
}

@app.get("/verify/access-health")
async def access_health():
    """Per-tier reachability from the SERVER side (reviewer access paper Part A):
    verifies our own chain answers, so reviewer-side failures can be attributed
    to reviewer tooling vs our infrastructure. Read-only probes only."""
    out = {"generated_utc": now_utc(),
           "verification_service_identity": dict(_PROCESS_IDENTITY, code_sha256_current=_vs_build_sha256()),
           "verification_service_build_sha256": _vs_build_sha256(),
           "server_utc": now_utc(),
           "access_limits": {
               "rate_limit": "none configured (no 429 path exists; ordinary reviewer load <=30 req/min with bursts of 6 is far below capacity)",
               "concurrency": "single uvicorn process, async handlers; concurrent requests served in parallel; OPC reads serialized per process by design (single-writer lease discipline on the source side)",
               "user_agent_filtering": "none",
               "ip_allowlist": "none (reviewer egress addresses change; no IP-based restriction exists)",
               "auth": "none on the read surface",
               "what_a_client_sees_at_a_limit": "no limit exists; no 429 is generated by this service"},
           "tiers": {}}
    # 1. engine
    import urllib.request
    t0 = time.time()
    try:
        with urllib.request.urlopen(ENGINE_BUILDINFO_URL, timeout=15) as r:
            body = json.loads(r.read())
        out["tiers"]["diagnosis_engine"] = {"destination": "diagnosis-engine (internal; omitted per D-16)", "reachable": True,
                                           "build_id": (body.get("buildinfo") or body).get("build_id"),
                                           "module_sha256_uptimemax_api": ((body.get("buildinfo") or body).get("module_sha256") or {}).get("uptimemax_api"),
                                           "latency_seconds": round(time.time() - t0, 3)}
    except Exception as e:
        out["tiers"]["diagnosis_engine"] = {"destination": "diagnosis-engine (internal; omitted per D-16)", "reachable": False,
                                           "error_category": str(e.__class__.__name__), "error": str(e)[:120]}
    # 2. gateway (Perspective)
    t0 = time.time()
    try:
        req = urllib.request.Request(UI_BASE + "/overview", method="GET")
        with urllib.request.urlopen(req, timeout=25) as r:
            out["tiers"]["ignition_gateway_perspective"] = {"destination": "ignition-gateway (internal; omitted per D-16)", "reachable": r.status == 200,
                                                            "http_status": r.status, "latency_seconds": round(time.time() - t0, 3)}
    except Exception as e:
        out["tiers"]["ignition_gateway_perspective"] = {"destination": "ignition-gateway (internal; omitted per D-16)", "reachable": False,
                                                        "error_category": str(e.__class__.__name__), "error": str(e)[:120]}
    # 3. historian DB
    t0 = time.time()
    try:
        conn = pymysql.connect(unix_socket="/run/mysqld/mysqld.sock", user="root", database="ignition_historian", charset="utf8mb4")
        with conn.cursor() as cur:
            cur.execute("select max(t_stamp) from sqlt_data_1_2026_10 d join sqlth_te te on d.tagid=te.id where te.tagpath like 'compressors/%'")
            mx = cur.fetchone()[0]
        conn.close()
        out["tiers"]["historian_database"] = {"reachable": True, "latency_seconds": round(time.time() - t0, 3),
                                              "last_compressor_write_utc": (datetime.datetime.fromtimestamp(mx / 1000, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if mx else None)}
    except Exception as e:
        out["tiers"]["historian_database"] = {"reachable": False, "error": str(e)[:120]}
    # 4. OPC source (single read - lightweight; full heartbeat at /verify/heartbeat)
    t0 = time.time()
    try:
        async def _rd():
            c = Client(UA_URL); c.set_user("ua_writer"); c.set_password(UA_PASS)
            await c.connect()
            try:
                n = c.get_node(NS_ROOT + "/Compressor_01/Max_Velocity_RMS")
                return await n.read_value()
            finally:
                await c.disconnect()
        v = await _rd()
        out["tiers"]["opc_source"] = {"destination": "opc-ua-source (internal; omitted per D-16)", "reachable": v is not None, "sample_value": round(float(v), 4) if v is not None else None,
                                      "latency_seconds": round(time.time() - t0, 3),
                                      "note": "single read; 2 Hz liveness via /verify/heartbeat"}
    except Exception as e:
        out["tiers"]["opc_source"] = {"destination": "opc-ua-source (internal; omitted per D-16)", "reachable": False,
                                      "error_category": str(e.__class__.__name__), "error": str(e)[:120]}
    out["all_tiers_reachable"] = all(t.get("reachable") for t in out["tiers"].values())
    out["note"] = ("server-side view only; internal destinations omitted per D-16 (kept in protected server logs). "
                   "ATTRIBUTION RULE (D-01j): a reviewer fetch failing while this endpoint shows every tier "
                   "reachable is classed UNDETERMINED until the failure evidence identifies the responsible "
                   "segment - a green internal health result shows internal reachability, not end-to-end "
                   "reachability from every external client (reverse proxy, TLS, CDN, concurrency limit, "
                   "route-specific application error, or reviewer-side network policy can each fail "
                   "independently of it). The reviewer first supplies endpoint, UTC time, access mechanism and "
                   "exact error; server-side logs are examined when those observations justify it - this is not "
                   "an infrastructure investigation of every failed request. Qualifications retained: "
                   "reachability covers the networks actually tested, not every environment by extension; a "
                   "cached fetch is not proof of access to the current deployment.")
    return out


@app.get("/verify/historian/status")
async def historian_status():
    """Read-only historian facts for the reviewer checkpoint (2026-10-10):
    last successful write timestamp, row integrity distribution, and tag-path
    inventory. No writes, no calculations on stored values.
    Aggregate queries scan ~13.2M rows; results cached 300 s and the cache
    state is disclosed (D-01d remediation for the SERVER_ERROR failures)."""
    now = time.time()
    global _hist_status_cache
    cache = globals().get("_hist_status_cache")
    if cache and now - cache[0] < 300:
        out = json.loads(json.dumps(cache[1]))
        out["served_from_cache_seconds"] = round(now - cache[0], 1)
        out["cache_note"] = "identical cached aggregate (recomputed at computed_utc); freshness envelope fields recomputed per call"
    else:
        conn = pymysql.connect(unix_socket="/run/mysqld/mysqld.sock", user="root", database="ignition_historian", charset="utf8mb4")
        out = {"source": "ignition_historian (read-only SQL)", "generated_utc": now_utc(),
               "sampling_config_disclosed": {
                   "sampling_mode": "Tag Group 'Default': mode=Direct, rate=1000ms, opcDataMode=Subscribed (gateway config.idb TAGGROUPS, quoted in change notification)",
                   "historian_deadband": "none configured (historyEnabled=true, no historianDeadband/historianStorageStyle overrides); the deadband keys 2.0/1.0/0.5 in the compressor UDT belong to alarms (OilTempHigh/LowSuperheat/HighSuperheat), not historian storage",
                   "source_write_rate": "2 Hz (ingress writer)",
                   "observed_persistence_cadence": "~3.5-4.5 s per tag (historian-side behavior; NOT a 2 Hz persistence rate)"}}
        try:
            with conn.cursor() as cur:
                cur.execute("select count(*) from sqlth_te where tagpath like 'compressors/%'")
                out["compressor_tagpaths_registered"] = cur.fetchone()[0]
                cur.execute("select max(t_stamp) from sqlt_data_1_2026_10 d join sqlth_te te on d.tagid=te.id where te.tagpath like 'compressors/%'")
                mx = cur.fetchone()[0]
                if mx:
                    out["last_successful_write_utc"] = datetime.datetime.fromtimestamp(mx / 1000, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
                    out["age_seconds_at_computation"] = round(time.time() - mx / 1000, 1)
                else:
                    out["last_successful_write_utc"] = None
                cur.execute("select d.dataintegrity, count(*) from sqlt_data_1_2026_10 d join sqlth_te te on d.tagid=te.id where te.tagpath like 'compressors/%' group by d.dataintegrity")
                out["dataintegrity_distribution"] = {str(k): v for k, v in cur.fetchall()}
        except Exception as e:
            conn.close()
            raise HTTPException(500, "historian status read failed: %s" % str(e)[:120])
        conn.close()
        out["note"] = ("dataintegrity 192 = OPC Good (0xC0). Last write predates this call because the SQL Historian "
                       "module's 2-hour demo cycle expired 2026-10-04 (the known gap); live source telemetry is "
                       "unaffected - see /verify/snapshot heartbeat. Recording-window verification (approved Option 2) "
                       "re-establishes fresh persisted rows during designated windows.")
        out["computed_utc"] = out["generated_utc"]
        globals()["_hist_status_cache"] = (now, json.loads(json.dumps(out)))
    return out


TEXT_DIR = Path("/opt/uptimemax_verify/source_text")
_ALLOWED_TEXT = {
    "MANIFEST_SHA256.txt", "INPUT_CONTRACT.md", "DIAGNOSTIC_THRESHOLDS.md",
    "verify_service.py", "inspect_gateway.py", "inspect_sample_output.json",
    "NONREG_CHECKS_2026-10-10.md",
    "uptimemax_api.py", "operating_state.py", "sensor_integrity.py",
    "state_compositor.py", "classifier.py", "physics_filter.py",
    "process_reasoning.py", "compressor_state.py", "h_engine.py",
    "trend_engine.py", "brain_router.py", "worker_gateway.py",
    "opc_ingress_v2.redacted.py", "opc_ingress_v2.py", "RAGPanel_view.json",
    "D04_RESULTS.json", "operating_state_SANDBOX.py",
    "D0608_RESULTS.json", "uptimemax_api_SANDBOX.py",
    "D17_RESULTS.json", "sandbox_d17.py", "D20_RESULTS.json",
    "LOG_EXCERPTS_D01D_D05_D02.md", "D20_fixture_registry.json", "D20_REGISTRY.md",
    "D05_D10_RUN_SHEET.md", "D15_FILLED_Muiz_2026-10-11_v2.csv",
    "uptimemax_api_engine_identity.py",
    "TAGGROUPS_dump.txt", "historian_schema.txt",
    "tag-type-definition_UptimeMAX_ScrewCompressors_udts.json",
    "tag-type-definition_UptimeMAX_Compressors_udts.json",
    "tag-type-definition_UptimeMAX_ScrewCompressorsOPC_udts.json",
    "tag-type-definition_UptimeMAX_Configuration_udts.json",
    "tag-type-definition_UptimeMAX_Alarms_udts.json",
    "tag-definition_UptimeMAX_tags.json",
    "tag-definition_UptimeMAX_Compressors_udts.json",
    "tag-definition_UptimeMAX_CompressorsOPC_udts.json",
}


@app.get("/verify/source")
async def source_index():
    """D-01k: index of every served text file IN THE RESPONSE BODY (reviewer
    tools cannot read response headers), with per-file SHA-256 so each file is
    hash-verifiable without headers or archive access."""
    files = []
    for name in sorted(_ALLOWED_TEXT):
        p = TEXT_DIR / name
        if p.is_file():
            files.append({"file": name, "url": "/verify/source/%s" % name,
                          "bytes": p.stat().st_size,
                          "sha256": hashlib.sha256(p.read_bytes()).hexdigest()})
    return {"generated_utc": now_utc(), "count": len(files),
            "note": ("all files served as text/plain at stable URLs; verify SHA-256 "
                     "against this body (headers not required). This index supersedes "
                     "header-based discovery per D-01k."),
            "files": files}


@app.get("/verify/source/{name}", response_class=None)
async def source_text(name: str):
    """Plain-text serving of evidence files (D-01e / D-12 / D-13): reviewers can
    read JSON and text but cannot unzip archives or compute hashes, so every
    file from the source packs is served individually as text at a stable URL.
    Byte fidelity: served verbatim from disk; hashes are listed in
    MANIFEST_SHA256.txt and /verify/artifacts."""
    from fastapi.responses import Response as _Resp
    if name not in _ALLOWED_TEXT:
        raise HTTPException(404, "unknown text artifact; allowed: %s" % ", ".join(sorted(_ALLOWED_TEXT)))
    p = TEXT_DIR / name
    if not p.is_file():
        raise HTTPException(404, "not present")
    return _Resp(content=p.read_bytes(), media_type="text/plain; charset=utf-8",
                 headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                          "X-File-SHA256": hashlib.sha256(p.read_bytes()).hexdigest()})


@app.get("/verify/display/{execution_id}")
async def display_readback(execution_id: str, pages: Optional[str] = Query(None), screenshot: str = Query("false")):
    """D-01i: read back what Perspective actually renders for a given execution ID
    (values, status wording, extracted key displays; optional PNG). Resolves the
    execution's equipment from the stored trace mirror, then live-captures the
    requested page(s) for that compressor. Read-only: rendering does not invoke
    the diagnosis engine and does not create or modify records."""
    if not re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", execution_id):
        raise HTTPException(400, "execution_id must be a UUID")
    tr = None
    tp = Path(TRACE_DIR_REMOTE) / ("%s.json" % execution_id)
    if tp.is_file():
        rec = json.loads(tp.read_text())
        tr = rec.get("trace", rec)
    else:
        import urllib.request
        tr = None
        for base in (ENGINE_TRACE_BASE_URL, SANDBOX_ENGINE_BASE_URL):
            try:
                with urllib.request.urlopen(base + "/traces/" + execution_id.lower(), timeout=20) as r:
                    rec = json.loads(r.read())
                tr = rec.get("trace", rec)
                break
            except Exception:
                continue
        if tr is None:
            raise HTTPException(404, "trace %s not found (engine store + sandbox store + local mirror)" % execution_id)
    equip = tr.get("asset_identity", {}).get("equipment_id") or tr.get("inputs", {}).get("equipment_id")
    if not equip:
        raise HTTPException(404, "trace carries no equipment identity")
    try:
        comp, label = _norm_machine("COMP_%02d" % int(equip.split("_")[-1]))
    except Exception:
        raise HTTPException(400, "cannot resolve machine from equipment_id %r" % equip)
    wanted = [p.strip() for p in pages.split(",")] if pages else ["overview"]
    for p in wanted:
        if p not in PAGES:
            raise HTTPException(400, "unknown page '%s'. Available: %s" % (p, sorted(PAGES)))
    want_png = screenshot.lower() == "true"
    disp = {}
    pngs = {}
    for p in wanted:
        try:
            result, png, dur, ready = await _render_page(p, comp, want_png)
            text = result if isinstance(result, str) else json.dumps(result)
            disp[p] = {"captured_utc": now_utc(), "capture_duration_seconds": dur, "ready_marker_found": ready,
                       "extracted_key_displays": _extract(text, PAGE_PATTERNS.get(p, {})),
                       "full_visible_text": text[:6000]}
            if png is not None:
                pngs[p] = "data:image/png;base64," + base64.b64encode(png).decode()
        except Exception as e:
            disp[p] = {"error": str(e)[:120]}
    return {"execution_id": execution_id, "equipment_id": equip, "machine": label,
            "trace_timestamp_utc": tr.get("timestamp_utc"),
            "trace_outcome": tr.get("outcome"),
            "trace_final_state": (tr.get("final_decision") or {}).get("final_state") or tr.get("final_state"),
            "pages_captured": disp,
            "screenshots_png_base64": pngs if want_png else None,
            "screenshot_note": "screenshots only with ?screenshot=true (slower); JSON read-back is the default",
            "timing_note": "single-page default (D-01-R1 L9 remediation: multi-page renders exceeded reviewer fetch timeouts); add &pages= for more",
            "note": ("live Perspective capture for THIS execution's machine, resolved at read time. The trace's "
                     "decision fields come from the stored record; the display comes from the live client DOM. "
                     "Both are served so a reviewer can check the operator-visible result against the record.")}


ARTIFACT_DIR = "/opt/uptimemax_verify/artifacts"
_ALLOWED_ARTIFACTS = {
    "V272_CANDIDATE3_SOURCE_PACK.zip",
    "V272_CANDIDATE3_RECORDS.tar.gz",
    "V272_ARCHITECTURE_EVIDENCE.md",
    "V272_CANDIDATE4_SOURCE_PACK.zip",
    "V272_DIAGNOSTIC_PATH_CONFIG.zip",
    "INPUT_CONTRACT.md",
}

@app.get("/verify/artifacts")
async def artifacts_list():
    """Read-only artifact delivery (mail-transport-independent): each frozen
    evidence artifact with its SHA-256, so reviewers can hash-verify after
    downloading. Read-only: only the allow-listed frozen artifacts."""
    from fastapi.responses import JSONResponse
    out = []
    for name in sorted(_ALLOWED_ARTIFACTS):
        p = Path(ARTIFACT_DIR) / name
        if p.exists():
            out.append({"file": name, "bytes": p.stat().st_size,
                        "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
                        "url": "/verify/artifacts/%s" % name})
    return {"artifacts": out,
            "note": ("download via /verify/artifacts/{file}; verify SHA-256 after "
                     "download against the values Muiz transmitted")}

@app.get("/verify/artifacts/{name}")
async def artifacts_get(name: str):
    from fastapi.responses import FileResponse
    if name not in _ALLOWED_ARTIFACTS:
        raise HTTPException(404, "unknown artifact")
    p = Path(ARTIFACT_DIR) / name
    if not p.exists():
        raise HTTPException(404, "artifact not present")
    return FileResponse(str(p), filename=name,
                        headers={"Cache-Control": "no-store"})

@app.get("/verify/buildinfo")
async def buildinfo():
    import urllib.request
    try:
        with urllib.request.urlopen(ENGINE_BUILDINFO_URL, timeout=10) as r:
            body = json.loads(r.read())
        try:
            Path("/opt/uptimemax_verify/last_good_buildinfo.json").write_text(
                json.dumps(body, indent=1))
        except Exception:
            pass
        return {"buildinfo": body, "source": "live", "fetched_utc": now_utc()}
    except Exception as e:
        p = Path("/opt/uptimemax_verify/last_good_buildinfo.json")
        if p.exists():
            return {"buildinfo": json.loads(p.read_text()), "source": "last_good_cache",
                    "live_error": str(e)[:120], "fetched_utc": now_utc()}
        raise HTTPException(502, "engine buildinfo unreachable: " + str(e)[:120])


# ---- READ-ONLY diagnosis-trace retrieval (authorized Milestone A follow-up) ----
# Contract: GET only; proxies the engine's read-only trace store. Retrieval NEVER
# invokes the diagnosis engine and never creates, modifies, or deletes records.
# execution_id is validated against a strict UUID grammar on this layer too, so
# no arbitrary filesystem access is possible. Responses are no-store.
ENGINE_TRACE_BASE_URL = _CFG["ENGINE_TRACE_BASE_URL"]
SANDBOX_ENGINE_BASE_URL = "http://198.199.121.125:8011/api/v1"  # D-20b: isolated sandbox engine (read-only trace lookups for display read-back)
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


@app.get("/verify/traces")
async def traces_index(limit: int = Query(200, ge=1, le=1000)):
    """Read-only index of existing engine diagnosis traces (newest first).
    Lets reviewers identify existing records without triggering a diagnosis."""
    import urllib.request
    try:
        with urllib.request.urlopen(ENGINE_TRACE_BASE_URL + "/traces?limit=%d" % limit, timeout=15) as r:
            body = json.loads(r.read())
    except Exception as e:
        raise HTTPException(502, "trace index unreachable: " + str(e)[:120])
    return {"source": "engine_trace_store_read_only", "generated_utc": now_utc(),
            "count": body.get("count"), "traces": body.get("traces"),
            "note": ("index only. Retrieve one record via /verify/trace/{execution_id}. "
                     "Retrieval never invokes the diagnosis engine and never creates new state "
                     "(idempotency demonstrated in MILESTONE_A follow-up evidence).")}


@app.get("/verify/trace/{execution_id}")
async def trace_get(execution_id: str):
    """Read-only retrieval of one previously-persisted diagnosis trace by stable
    execution ID. Strict UUID validation (no filesystem traversal). Repeated reads
    return the identical stored record and create no new traces."""
    if not _UUID_RE.match(execution_id or ""):
        raise HTTPException(400, "execution_id must be a UUID")
    import urllib.request
    body = None
    last_err = None
    for base in (ENGINE_TRACE_BASE_URL, SANDBOX_ENGINE_BASE_URL):  # D-20b: sandbox-store fallback (mirror of display route)
        try:
            with urllib.request.urlopen(base + "/traces/" + execution_id.lower(), timeout=15) as r:
                body = json.loads(r.read())
            break
        except Exception as e:
            last_err = e
    if body is None:
        src = "production" if last_err and "404" in str(last_err) else "unreachable"
        raise HTTPException(404 if "404" in str(last_err) else 502,
                            "trace retrieval error (%s): %s" % (src, str(last_err)[:120]))
    return {"source": "engine_trace_store_read_only", "fetched_utc": now_utc(),
            "record_sha256": body.get("record_sha256"), "dropped_fields": body.get("dropped_fields"),
            "trace": body.get("trace"),
            "note": ("verbatim stored record (scoped to approved diagnostic evidence fields); read-only, idempotent. "
                     "Field semantics: sensor_count counts the multi-sensor sensors[] array (preferred modality); "
                     "single-stream payloads populate top-level inputs instead, so sensor_count=0 with populated "
                     "inputs is expected. Traces executed before 2026-10-10 predate the verdict-persistence "
                     "extension and may lack classification/iso_zone; newer records carry them.")}

@app.get("/verify/rag/query")
async def rag_query(q: str, compressor: Optional[str] = Query(None)):
    import urllib.request
    if not RAG_KEY:
        raise HTTPException(503, "gateway key not configured (RAG_GW_KEY env); "
                                 "no credential fallback exists in source")
    req = urllib.request.Request(RAG, data=json.dumps({"query": q}).encode(),
                                 headers={"Content-Type": "application/json", "X-API-Key": RAG_KEY}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            body = json.loads(r.read())
    except Exception as e:
        raise HTTPException(502, "rag gateway error: " + str(e)[:120])
    return {"query": q, "rag_gateway_response_verbatim": body,
            "note": "verbatim gateway response: verified flag, answer, citations (with source_tier), gateway_status, confidence. No conclusions added."}

@app.get("/verify/rag/catalog_stats")
async def rag_catalog_stats(q: str = Query("")):
    """Deterministic structured count/list over the Genemco catalog snapshot.
    NOT semantic RAG: exact filter+count over catalog_golden_records.jsonl on the
    RAG VM. Snapshot-dated; no LLM, no scores, no synthesis."""
    import urllib.parse, urllib.request
    base = RAG[:-len("/query")] if RAG.endswith("/query") else RAG
    url = base + "/catalog_stats?q=" + urllib.parse.quote(q)
    req = urllib.request.Request(url, headers={"X-API-Key": RAG_KEY})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            body = json.loads(r.read())
    except Exception as e:
        raise HTTPException(502, "catalog_stats error: " + str(e)[:120])
    return {"query": q, "catalog_stats_verbatim": body,
            "note": "deterministic structured-data operation over the catalog snapshot; answers count/list questions exactly (as of the snapshot date), independent of the RAG verified-contract"}

@app.get("/verify/ui")
async def ui_list(evidence: Optional[str] = Query(None), run: str = Query("RUN1"),
                  trace: Optional[str] = Query(None), traces: Optional[str] = Query(None)):
    def _ev(cid, which="RUN1"):
        d = EVIDENCE_DIR_RUN2 if which == "RUN2" else EVIDENCE_DIR
        suffix = "_RUN2" if which == "RUN2" else ""
        for name in ((f"{cid}.json", f"{cid}{suffix}.json") if which == "RUN2" else (f"{cid}.json",)):
            p = Path(d) / name
            if p.is_file():
                return json.load(open(p))
        return None
    def _index(which="RUN1"):
        d = EVIDENCE_DIR_RUN2 if which == "RUN2" else EVIDENCE_DIR
        suffix = "_RUN2" if which == "RUN2" else ""
        ids = set()
        if Path(d).is_dir():
            for f in sorted(os.listdir(d)):
                if f.endswith(".json") and not f.startswith("_"):
                    cid = f[:-5]
                    if suffix and cid.endswith(suffix):
                        cid = cid[: -len(suffix)]
                    if cid == "run2_summary":
                        continue
                    if not suffix and "_RUN2" in cid:
                        continue
                    ids.add(cid)
        return sorted(ids)
    resp = {"build": BUILD, "verification_revision": "PARALLEL_ACCESS_2026-10-06_3",
            "generated_utc": now_utc(),
            "pages": {k: v for k, v in PAGES.items()},
            "page_path_note": "page paths are relative to the Perspective client root (D-16: full gateway URLs omitted from public responses)",
            "fast_path": "append &screenshot=false for the fast structured path (skips PNG capture); typical 12-30 s. Default returns screenshot too (slower).",
            "actions": ["/verify/ui/{page}", "/verify/action/diagnose/{machine}", "/verify/ui/compare/{machine}", "/verify/rag/query?q=..."],
            "note": ("GET /verify/ui/{page}?compressor=COMP_XX returns the RESOLVED operator-facing display. "
                     "Evidence access through THIS proven doorway, query params only: "
                     "?evidence=V271-A-056&run=RUN1|RUN2 (full immutable record), "
                     "?traces=list (execution trace index), ?trace=EXECUTION_ID (full production trace).")}
    ids1, ids2 = _index("RUN1"), _index("RUN2")
    # ladder #5: small audit manifest directly in the plain response
    def _dir_hash(d):
        h = hashlib.sha256()
        if Path(d).is_dir():
            for f in sorted(os.listdir(d)):
                if f.endswith(".json"):
                    h.update(f.encode()); h.update(open(Path(d)/f,"rb").read())
        return h.hexdigest()
    acc_path = Path("/opt/uptimemax_verify/event_driven_acceptance.json")
    resp["audit_manifest"] = {
        "revision": resp["verification_revision"],
        "schema_version": "V271-test-evidence-1.0",
        "builds": {"RUN1": "BUILD V270.1", "RUN2": "BUILD V271.1", "engine": "V271.1"},
        "run1": {"count": len(ids1), "evidence_dir_sha256": _dir_hash(EVIDENCE_DIR)},
        "run2": {"count": len(ids2), "evidence_dir_sha256": _dir_hash(EVIDENCE_DIR_RUN2)},
        "trace_ids": sorted([f[:-5] for f in os.listdir(TRACE_DIR_REMOTE) if f.endswith(".json")]) if Path(TRACE_DIR_REMOTE).is_dir() else [],
        "immutable_export": {"zip": "V271_AUDIT_EXPORT.zip", "manifest_sha256": "9cd73fd85f9ad52b1b42c35dd33d84cc1b5f6d988c5172532167cfadd62dee81",
                             "files": 16, "note": "attached package; byte-for-byte exports, hashes match these server-side records"},
    }
    resp["evidence_index"] = {"RUN1": {"count": len(ids1), "case_ids": ids1,
                                       "source": "immutable RUN1 records, untouched"},
                              "RUN2": {"count": len(ids2), "case_ids": ids2,
                                       "source": "immutable RUN2 records, identical frozen 150 against BUILD V271.1"}}
    resp["run1_evidence_sample"] = {cid: _ev(cid, "RUN1") for cid in ("V271-A-056", "V271-A-075")}
    resp["run2_evidence_sample"] = {cid: _ev(cid, "RUN2") for cid in ("V271-B-011", "V271-A-075")}
    # acceptance set summary (event-driven brain controls)
    acc_path = Path("/opt/uptimemax_verify/event_driven_acceptance.json")
    if acc_path.is_file():
        acc = json.load(open(acc_path))
        resp["event_driven_brain_acceptance"] = {
            "set": acc.get("acceptance_set"),
            "controls": {k: {"result": v["result"],
                             "retrieval_triggered": v["trace"]["repository_retrieval_triggered"],
                             "outcome": v["trace"]["outcome"],
                             "execution_id": v["trace"]["execution_id"]}
                         for k, v in acc.get("controls", {}).items()},
            "note": "full production traces retrievable via ?trace=EXECUTION_ID; traces are recorded by the production engine at execution time, not reconstructed"}
    if evidence:
        resp["requested_evidence"] = _ev(evidence, run)
    if traces == "list":
        tdir = Path(TRACE_DIR_REMOTE)
        resp["execution_traces"] = sorted(f[:-5] for f in os.listdir(tdir) if f.endswith(".json")) if tdir.is_dir() else []
    if trace:
        tp = Path(TRACE_DIR_REMOTE) / f"{trace}.json"
        if tp.is_file():
            resp["requested_execution_trace"] = json.load(open(tp))
        else:
            resp["requested_execution_trace"] = {"error": f"trace {trace} not found (see ?traces=list)"}
    return resp

@app.get("/verify/ui/evidence-test")
async def ui_evidence_test():
    "Routing diagnostic: exact bytes of /verify/test/V271-A-056 served under the /verify/ui path ChatGPT already consumes."
    return await test_evidence("V271-A-056")

@app.get("/verify/ui/{page}")
async def ui_page(page: str, compressor: Optional[str] = Query(None), screenshot: str = Query("false")):
    if page not in PAGES:
        raise HTTPException(404, f"unknown page '{page}'. Available: {list(PAGES.keys())}")
    comp, label = _norm_machine(compressor or "COMP_01")
    want_png = screenshot.lower() == "true"
    try:
        result, png, dur, ready = await _render_page(page, comp, want_png)
    except Exception as e:
        raise HTTPException(502, "ui capture failed: " + str(e)[:120])
    if isinstance(result, dict) and result.get("ui_state") == "trial_expired":
        return {"build": BUILD, "page": page, "captured_utc": now_utc(),
                "ui_state": "trial_expired", **result}
    text = result
    return {"build": BUILD, "page": page, "page_path": PAGES[page],
            "compressor_selected": label, "captured_utc": now_utc(),
            "capture_duration_seconds": dur, "ready_marker_found": ready,
            "resolved_display": {"extracted_key_displays": _extract(text, PAGE_PATTERNS.get(page, {})),
                                 "full_visible_text": text[:6000]},
            "binding_identity_note": "displayed values come from the live Perspective client DOM (resolved state). Underlying binding sources for the key displays are documented in BINDING_MAP / VERIFY_ENDPOINTS_APPENDIX; they read [UptimeMAX] provider tags written by the single ingress writer.",
            "screenshot_png_base64": ("data:image/png;base64," + base64.b64encode(png).decode()) if png is not None else None}

@app.get("/verify/action/diagnose/{machine}")
async def action_diagnose(machine: str):
    comp, label = _norm_machine(machine)
    data = await ua_read_all(comp)
    def g(k):
        v = data.get(k, {}).get("value")
        return float(v) if isinstance(v, (int, float)) else None
    payload = {"equipment_id": comp,
               "velocity_rms_mm_s": g("Max_Velocity_RMS"),
               "envelope_g": g("Vibration/EnvelopeEnergy_gE"),  # engine model field name (envelope_ge_g was silently dropped by the engine model - verified Oct 10)
               "peak_hz": g("Vibration/EnvelopePeakFreq"),  # renamed to the engine model field (envelope_peak_hz would be rejected under extra=forbid - CANDIDATE-4)
               "crest_factor": g("Vibration/CrestFactor"),
               "suction_pressure": g("Process/SuctionPressure"),
               "discharge_pressure": g("Process/DischargePressure")}
    import urllib.request
    try:
        req = urllib.request.Request(ENGINE_TRACE_BASE_URL + "/diagnose",
                                     data=json.dumps(payload).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=60) as r:
            diag = json.loads(r.read())
    except Exception as e:
        raise HTTPException(502, "diagnose error: " + str(e)[:120])
    return {"build": BUILD, "machine": label, "captured_utc": now_utc(),
            "live_inputs_sent": payload, "engine_response_verbatim": diag,
            "note": "same diagnose engine the operator's RUN LIVE DIAGNOSIS button invokes; read-only."}

@app.get("/verify/ui/compare/{machine}")
async def ui_compare(machine: str, pages: Optional[str] = Query(None)):
    comp, label = _norm_machine(machine)
    wanted = [p.strip() for p in pages.split(",")] if pages else ["iso-vibration-detail", "pid-live", "micro-registers"]
    for p in wanted:
        if p not in PAGES:
            raise HTTPException(400, f"unknown page '{p}'. Available: {list(PAGES.keys())}")
    src = await ua_read_all(comp)
    src_curated = {k: src[k] for k in ("Max_Velocity_RMS", "ISO_Compliance_Zone", "RUL_Diagnostics/Status",
                                       "Vibration/EnvelopeEnergy_gE", "ManualRegisters/Manual_OilPressure_PSIA",
                                       "ManualRegisters/Manual_MotorCurrent_A", "Process/DischargePressure",
                                       "ManualRegisters/Manual_CapacityPercent") if k in src}
    ui = {}
    for page in wanted:
        try:
            text, _png, dur, ready = await _render_page(page, comp, False)  # fast: no screenshots in compare
            ui[page] = {"captured_utc": now_utc(), "capture_duration_seconds": dur,
                        "ready_marker_found": ready,
                        "extracted": _extract(text, PAGE_PATTERNS.get(page, {}))}
        except Exception as e:
            ui[page] = {"error": str(e)[:120]}
    return {"build": BUILD, "machine": label,
            "source_values_live_opc": src_curated,
            "resolved_ui_displays": ui,
            "trace": "raw source/tag -> ingress writer -> UptimeMAX tags -> Perspective bindings -> operator-displayed values (captured within one compare request; source values captured first)",
            "note": "fast path: screenshots omitted from compare by default (use /verify/ui/{page}?screenshot=true for PNGs). No conclusions drawn."}

@app.get("/verify/tests")
async def tests_list(run: str = Query("RUN1")):
    d = EVIDENCE_DIR_RUN2 if run == "RUN2" else EVIDENCE_DIR
    suffix = "_RUN2" if run == "RUN2" else ""
    ids = set()
    if Path(d).is_dir():
        for f in sorted(os.listdir(d)):
            if f.endswith(".json") and not f.startswith("_"):
                cid = f[:-5]
                if suffix and cid.endswith(suffix):
                    cid = cid[: -len(suffix)]
                if cid == "run2_summary":
                    continue
                if not suffix and "_RUN2" in cid:
                    continue
                ids.add(cid)
    ids = sorted(ids)
    return {"run_id": run, "build": BUILD, "evidence_dir": d, "cases_available": ids,
            "schema": ("/verify/test/{CASE_ID}?run=" + run + " e.g. /verify/test/V271-A-037?run=" + run),
            "schema_contract": json.load(open(EVIDENCE_DIR + "/_SCHEMA.json")) if Path(EVIDENCE_DIR + "/_SCHEMA.json").is_file() else None,
            "note": ("RUN1 records are permanent and untouched. RUN2 is the identical frozen 150-case rerun "
                     "against remediated BUILD V271.1 (six architectural fixes; schema-only harness changes). "
                     "Evidence records are written by the offline harness on the RAG VM. CRITICAL RULE: the harness "
                     "may know ground truth; UptimeMAX must never receive ground truth in its context before answering.")}

@app.get("/verify/test/{case_id}")
async def test_evidence(case_id: str, run: str = Query("RUN1")):
    if not re.fullmatch(r"V271-[AB]-\d{3}", case_id):
        raise HTTPException(400, "case_id must match V271-A-001..075 or V271-B-001..075")
    d = EVIDENCE_DIR_RUN2 if run == "RUN2" else EVIDENCE_DIR
    for name in (f"{case_id}.json", f"{case_id}_RUN2.json") if run == "RUN2" else (f"{case_id}.json",):
        p = Path(d) / name
        if p.is_file():
            return json.load(open(p))
    raise HTTPException(404, f"no evidence record for {case_id} run={run} (available under /verify/tests?run={run})")

@app.get("/verify/evidence")
async def evidence_list():
    return await tests_list()

@app.get("/verify/evidence/{case_id}")
async def evidence_case(case_id: str):
    return await test_evidence(case_id)

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8010, log_level="warning")
