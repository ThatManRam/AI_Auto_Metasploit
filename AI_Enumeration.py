# ai_commander_nmap_allports.py
import json, os, re, subprocess, sys
from datetime import datetime
import ollama

# ------------ CONFIG ------------
MODEL = "mistral"
TARGET_IP = "192.168.56.101"          # change if needed
MAX_STEPS = 10
TIMEOUT_SEC = 15                 # per follow-on command
NMAP_TIMEOUT_SEC = 240           # allow time for full -p- scan
LOG_DIR = "ai_runs"

# ------------ SAFETY ------------
DANGEROUS_PATTERNS = re.compile(
    r"(?:\b(?:rm\s+-rf|rm\s+-fr|mkfs|fdisk|parted|dd\s+if=|:>\s*/|truncate\s+-s|"
    r"chmod\s+([0-7]{3}|[+-][rwxXstugo]+)\s+-R\s+/|chown\s+-R\s+/|mv\s+/.+|"
    r"shutdown\b|reboot\b|poweroff\b|halt\b|swapoff\b|kill\s+-9\s+1\b|mount\s+-o\s+remount[,=]rw\s+/)"
    r"|:\(\)\s*{\s*:\s*\|\s*:\s*&\s*}\s*;\s*:\s*$)",
    re.IGNORECASE
)

def is_safe(cmd: str) -> bool:
    if not cmd or not cmd.strip():
        return False
    if cmd.strip() in {"bash", "sh"}:
        return False
    return not bool(DANGEROUS_PATTERNS.search(cmd))

def run_cmd(cmd: str, timeout: int):
    return subprocess.run(
        ["bash", "-lc", cmd],
        capture_output=True,
        text=True,
        timeout=timeout
    )

def ensure_logdir():
    os.makedirs(LOG_DIR, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = os.path.join(LOG_DIR, f"run_{stamp}")
    os.makedirs(run_dir, exist_ok=True)
    return run_dir

def write_json(path, payload):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

def truncate(s, limit=8000):
    if s is None:
        return ""
    return s if len(s) <= limit else s[:limit] + "…[truncated]"

# Parse normal nmap output lines like: "22/tcp open  ssh"
def parse_nmap_text(stdout: str):
    open_ports = []
    for line in stdout.splitlines():
        line = line.strip()
        m = re.match(r"^(\d+)\/(tcp|udp)\s+open\s+(\S+)", line)
        if m:
            port = int(m.group(1))
            proto = m.group(2)
            service = m.group(3)
            open_ports.append({"port": port, "proto": proto, "service": service})
    return open_ports

# ------------ PROMPTS ------------
SYSTEM_PROMPT = f"""
You are a *non-destructive* lab assistant. We've already run "nmap -p- TARGET_IP" and will give you:
1) a compact JSON list of open ports/services (parsed from the text output),
2) the raw nmap stdout (possibly truncated).

Using that, propose exactly ONE safe, quick shell command to enumerate the most promising service next.
Return STRICT JSON only:
{{
  "thoughts": "brief reasoning",
  "command": "single shell command to run next, or empty if none",
  "explanation": "1-2 sentence why this command helps",
  "done": false
}}

Rules:
- Non-destructive only. No writes to system files, no privilege escalation, no service disruption.
- Prefer quick, bounded flags/timeouts (e.g., curl -I -m 5, openssl s_client -connect HOST:PORT </dev/null | head -n 40).
- Tailor to service:
  - HTTP(S): curl -I -m 5 http://HOST:PORT or https://HOST:PORT
  - TLS generic: openssl s_client -connect HOST:PORT -servername HOST </dev/null | head -n 40
  - SSH: ssh -o BatchMode=yes -o ConnectTimeout=5 -G HOST | head -n 20  (non-interactive)
  - FTP: echo QUIT | nc -v -w 3 HOST 21
  - SMTP: echo -e "EHLO test\\r\\nQUIT\\r\\n" | nc -v -w 5 HOST 25
  - MySQL: echo | nc -v -w 3 HOST 3306  (banner peek)
  - Postgres: echo | nc -v -w 3 HOST 5432
  - Redis: echo -e "PING\\r\\n" | nc -v -w 3 HOST 6379
  - Generic TCP: echo | nc -v -w 3 HOST PORT
- If nothing else is useful, set "done": true and give a short summary.
Target IP is {TARGET_IP}.
"""

GOAL = "Plan the safest, most informative single next command based on the nmap -p- results."

def parse_model_json(content: str):
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass
    m = re.search(r"\{.*\}", content, flags=re.S)
    if m:
        return json.loads(m.group(0))
    m = re.search(r'(?m)^(?:`+)?([a-zA-Z0-9_-]+(?:\s+[^\n`]+)?)', content)
    if m:
        return {"thoughts": "fallback parse", "command": m.group(1), "explanation": "", "done": False}
    raise ValueError("Strict JSON not found")

# ------------ MAIN ------------
def main():
    run_dir = ensure_logdir()

    # 0) FIRST COMMAND: exactly "nmap -p- <TARGET_IP>"
    nmap_cmd = f"nmap -p- {TARGET_IP}"
    print(f"[Bootstrap] Running first command exactly: {nmap_cmd}")
    try:
        proc = run_cmd(nmap_cmd, timeout=NMAP_TIMEOUT_SEC)
        nmap_rc, nmap_out, nmap_err = proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        nmap_rc, nmap_out, nmap_err = None, "", f"Timeout after {NMAP_TIMEOUT_SEC}s"

    open_ports = parse_nmap_text(nmap_out)
    bootstrap_record = {
        "command": nmap_cmd,
        "returncode": nmap_rc,
        "stdout": truncate(nmap_out, 120000),
        "stderr": truncate(nmap_err, 20000),
        "parsed_open": open_ports
    }
    write_json(os.path.join(run_dir, "step_00_nmap_allports.json"), bootstrap_record)

    # Seed the conversation
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"open_ports_summary: {json.dumps(open_ports)}"},
        {"role": "user", "content": f"raw_nmap_stdout_truncated:\n{truncate(nmap_out, 40000)}"},
        {"role": "user", "content": GOAL},
    ]

    # 1) Iterative loop based on what nmap found
    for step in range(1, MAX_STEPS + 1):
        resp = ollama.chat(model=MODEL, messages=messages, options={"temperature": 0})
        content = resp.get("message", {}).get("content", "")
        write_json(os.path.join(run_dir, f"step_{step:02d}_assistant_raw.json"), {"assistant_raw": content})

        try:
            j = parse_model_json(content)
        except Exception as e:
            messages.append({"role": "user", "content": f"Parser error: {e}. Please reply with strict JSON only."})
            continue

        command = (j.get("command") or "").strip()
        done = bool(j.get("done", False))
        write_json(os.path.join(run_dir, f"step_{step:02d}_assistant.json"), j)

        if done or not command:
            print(f"[Step {step}] Assistant indicated done.")
            messages.append({"role": "user", "content": "Provide a concise final summary of findings and suggested manual next steps."})
            final = ollama.chat(model=MODEL, messages=messages, options={"temperature": 0})
            final_text = final.get("message", {}).get("content", "").strip()
            write_json(os.path.join(run_dir, "final_summary.json"), {"final_summary": final_text})
            print("\n=== FINAL SUMMARY ===\n" + final_text)
            print(f"\nLogs saved to: {run_dir}")
            return

        if not is_safe(command):
            print(f"[Step {step}] BLOCKED (unsafe): {command}")
            feedback = {
                "result": {
                    "error": "blocked_by_policy",
                    "message": "Command blocked by policy. Propose a safe, quick alternative.",
                    "blocked_command": command
                }
            }
            messages.append({"role": "user", "content": json.dumps(feedback)})
            write_json(os.path.join(run_dir, f"step_{step:02d}_blocked.json"), feedback)
            continue

        print(f"[Step {step}] Running: {command}")
        try:
            proc = run_cmd(command, timeout=TIMEOUT_SEC)
            rc, out, err = proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired:
            rc, out, err = None, "", f"Timeout after {TIMEOUT_SEC}s"
        except Exception as e:
            rc, out, err = None, "", f"Execution error: {e}"

        result_for_model = {
            "executed_command": command,
            "returncode": rc,
            "stdout": truncate(out),
            "stderr": truncate(err),
        }
        write_json(os.path.join(run_dir, f"step_{step:02d}_result.json"), result_for_model)

        messages.append({"role": "user", "content": json.dumps({"result": result_for_model}, ensure_ascii=False)})

    # MAX_STEPS reached
    messages.append({"role": "user", "content": "Max step limit reached. Provide a concise summary of findings so far."})
    final = ollama.chat(model=MODEL, messages=messages, options={"temperature": 0})
    final_text = final.get("message", {}).get("content", "").strip()
    write_json(os.path.join(run_dir, "final_summary.json"), {"final_summary": final_text})
    print("\n=== FINAL SUMMARY ===\n" + final_text)
    print(f"\nLogs saved to: {run_dir}")

if __name__ == "__main__":
    main()
