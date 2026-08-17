import os
import platform
import subprocess
import shlex
import sys
import re
import ipaddress
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

TOOLS_DIR = os.path.join(BASE_DIR, "tools")
DUMP_DIR = os.path.join(BASE_DIR, "dumps")
RESULTS_DIR = os.path.join(BASE_DIR, "results")

VOL_PATH = os.path.join(TOOLS_DIR, "volatility3-develop", "vol.py")
WINPMEM_PATH = os.path.join(TOOLS_DIR, "winpmem.exe")

os.makedirs(DUMP_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)

SCAN_CATALOG = {
    "Windows": {
        "Processes": {
            "plugin": "windows.pslist",
            "description": "Lists running processes and parent-child relationships."
        },
        "Network Connections": {
            "plugin": "windows.netscan",
            "description": "Displays open network sockets, ports, and remote connections."
        },
        "Command Line": {
            "plugin": "windows.cmdline",
            "description": "Shows command-line arguments used to start processes."
        },
        "File Artifacts": {
            "plugin": "windows.filescan",
            "description": "Scans memory for file objects referenced by the system."
        },
        "DLL List": {
            "plugin": "windows.dlllist",
            "description": "Lists DLLs loaded by each process."
        },
        "Handles": {
            "plugin": "windows.handles",
            "description": "Shows open handles such as files, registry keys, and events."
        },
        "Services": {
            "plugin": "windows.svcscan",
            "description": "Shows Windows services present in memory."
        },
        "Injected Code Detection": {
            "plugin": "windows.malfind",
            "description": "Detects suspicious injected or executable memory regions."
        }
    },
    "Linux": {
        "Processes": {
            "plugin": "linux.pslist.PsList",
            "description": "Lists running processes and process hierarchy."
        },
        "Network Connections": {
            "plugin": "linux.sockstat.Sockstat",
            "description": "Shows socket and network-related information."
        },
        "Command History": {
            "plugin": "linux.bash.Bash",
            "description": "Extracts bash command history artifacts from memory."
        },
        "Open Files": {
            "plugin": "linux.lsof.Lsof",
            "description": "Lists open files associated with running processes."
        },
        "Loaded Kernel Modules": {
            "plugin": "linux.lsmod.Lsmod",
            "description": "Shows kernel modules currently loaded in memory."
        },
        "Process Environment": {
            "plugin": "linux.envars.Envars",
            "description": "Displays environment variables for processes."
        },
        "Hidden Processes": {
            "plugin": "linux.psscan.PsScan",
            "description": "Scans memory for processes not visible in standard lists."
        },
        "Suspicious Memory Regions": {
            "plugin": "linux.malfind.Malfind",
            "description": "Searches for suspicious executable memory areas."
        }
    }
}

PRESET_SCANS = {
    "Windows": {
        "Quick Triage": [
            "Processes",
            "Network Connections",
            "Command Line"
        ],
        "Full Snapshot": [
            "Processes",
            "Network Connections",
            "Command Line",
            "File Artifacts",
            "DLL List"
        ]
    },
    "Linux": {
        "Quick Triage": [
            "Processes",
            "Network Connections",
            "Command History"
        ],
        "Full Snapshot": [
            "Processes",
            "Network Connections",
            "Command History",
            "Open Files",
            "Loaded Kernel Modules"
        ]
    }
}


def detect_os():
    os_type = platform.system()
    print(f"[INFO] OS detected: {os_type}")
    return os_type


def detect_dump_os(dump_path):
    tests = {
        "Windows": "windows.info.Info",
        "Linux": "banners.Banners"
    }

    for os_type, plugin in tests.items():
        try:
            env = os.environ.copy()
            env["PYTHONIOENCODING"] = "utf-8"
            env["PYTHONUTF8"] = "1"

            result = subprocess.run(
                [sys.executable, "-X", "utf8", VOL_PATH, "-f", dump_path, plugin],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=env
            )

            stdout = result.stdout.strip()
            stderr = result.stderr.strip()

            if result.returncode == 0 and stdout:
                return os_type

            combined = f"{stdout}\n{stderr}".lower()
            if "volatility 3 framework" in combined and "unsatisfied requirement" not in combined:
                return os_type

        except Exception:
            pass

    return None


def get_available_plugins(os_type):
    try:
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONUTF8"] = "1"
        
        result = subprocess.run(
            [sys.executable, "-X", "utf8", VOL_PATH, "--help"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            timeout=30
        )
        
        all_output = result.stdout + "\n" + result.stderr
        plugins = []
        os_prefix = ""
        if os_type == "Windows":
            os_prefix = "windows."
        elif os_type == "Linux":
            os_prefix = "linux."
        
        for line in all_output.splitlines():
            line = line.strip()
            if os_prefix and line.startswith(os_prefix):
                parts = line.split()
                if len(parts) >= 1 and "." in parts[0]:
                    plugins.append(parts[0])
            elif not os_prefix and (line.startswith("windows.") or line.startswith("linux.")) and "." in line:
                parts = line.split()
                if len(parts) >= 1 and "." in parts[0]:
                    plugins.append(parts[0])
        
        return sorted(set(plugins))
    except Exception as e:
        return []


def get_available_scans(os_type):
    return SCAN_CATALOG.get(os_type, {})


def get_preset_scans(os_type, preset_name):
    return PRESET_SCANS.get(os_type, {}).get(preset_name, [])


def acquire_memory(os_type):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    dump_file = os.path.join(DUMP_DIR, f"memory_{timestamp}.raw")

    if os_type == "Windows":
        if not os.path.exists(WINPMEM_PATH):
            print("[ERROR] winpmem.exe not found in tools folder")
            return None

        try:
            print("[INFO] Acquiring RAM with WinPmem...")
            subprocess.run(
                [WINPMEM_PATH, "acquire", dump_file],
                check=True
            )
        except subprocess.CalledProcessError as e:
            print(f"[ERROR] RAM snapshot failed: {e}")
            return None

    elif os_type == "Linux":
        print("[ERROR] Linux acquisition is handled in acquisition/ram_capture.py")
        return None

    else:
        print(f"[ERROR] Unsupported OS: {os_type}")
        return None

    print(f"[INFO] Memory dump saved: {dump_file}")
    return dump_file


def build_suspicious_summary(results, os_type):
    findings = []

    suspicious_process_names = [
        "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
        "rundll32.exe", "mshta.exe", "regsvr32.exe", "wmic.exe",
        "bash", "sh", "python", "perl", "nc", "netcat"
    ]

    suspicious_keywords = [
        "-enc", "-encodedcommand", "frombase64string",
        "http://", "https://", "appdata", "\\temp\\", "/tmp/",
        ".ps1", ".bat", ".vbs", ".js", "downloadstring", "iex ",
        "invoke-expression", "curl ", "wget "
    ]

    process_text = results.get("Processes", "").lower()
    cmdline_text = (
        results.get("Command Line", "").lower()
        + "\n" +
        results.get("Command History", "").lower()
    )
    network_text = results.get("Network Connections", "").lower()
    files_text = results.get("File Artifacts", "").lower()
    open_files_text = results.get("Open Files", "").lower()
    hidden_text = results.get("Hidden Processes", "").lower()
    malfind_text = results.get("Injected Code Detection", "").lower()
    suspicious_mem_text = results.get("Suspicious Memory Regions", "").lower()

    for proc in suspicious_process_names:
        if proc in process_text or proc in cmdline_text:
            findings.append(f"[MEDIUM] Suspicious or dual-use process detected: {proc}")

    for keyword in suspicious_keywords:
        if keyword in cmdline_text:
            findings.append(f"[HIGH] Suspicious command-line indicator detected: {keyword}")

    if "established" in network_text or "tcp" in network_text or "udp" in network_text:
        findings.append("[MEDIUM] Network activity was found. Review Network Connections tab.")

    if "appdata" in cmdline_text or "appdata" in files_text:
        findings.append("[MEDIUM] Execution or file references from AppData detected.")

    if "\\temp\\" in cmdline_text or "\\temp\\" in files_text or "/tmp/" in cmdline_text or "/tmp/" in open_files_text:
        findings.append("[MEDIUM] Temporary-directory execution or file usage detected.")

    if "powershell.exe" in cmdline_text and ("-enc" in cmdline_text or "-encodedcommand" in cmdline_text):
        findings.append("[HIGH] PowerShell with encoded command detected.")

    if hidden_text.strip() and "no significant results found" not in hidden_text:
        findings.append("[HIGH] Hidden process scan returned results. Review Hidden Processes tab.")

    if malfind_text.strip() and "no significant results found" not in malfind_text:
        findings.append("[HIGH] Potential injected code or suspicious executable memory detected.")

    if suspicious_mem_text.strip() and "no significant results found" not in suspicious_mem_text:
        findings.append("[HIGH] Suspicious executable memory regions detected.")

    if not findings:
        findings.append("[INFO] No obvious suspicious indicators were automatically identified.")
        findings.append("[INFO] Manual review is still recommended.")

    return "\n".join(dict.fromkeys(findings))


def analyze_memory_by_tabs(
    dump_path,
    os_type,
    selected_scans,
    progress_callback=None,
    log_callback=None
):
    base_result = {
        "General Log": "",
        "Suspicious Findings": "",
        "Advanced Output": "",
        "Processes": "",
        "Network Connections": "",
        "Command Line": "",
        "File Artifacts": "",
        "DLL List": "",
        "Handles": "",
        "Services": "",
        "Injected Code Detection": "",
        "Command History": "",
        "Open Files": "",
        "Loaded Kernel Modules": "",
        "Process Environment": "",
        "Hidden Processes": "",
        "Suspicious Memory Regions": ""
    }

    if not os.path.exists(dump_path):
        base_result["General Log"] = "[ERROR] Memory dump file not found."
        return base_result

    if os_type == "Auto-detect":
        if log_callback:
            log_callback("[INFO] Auto-detecting dump OS...")
        detected_os = detect_dump_os(dump_path)
        if not detected_os:
            base_result["General Log"] = "[ERROR] Could not determine dump OS automatically."
            return base_result
        os_type = detected_os

    scan_map = SCAN_CATALOG.get(os_type)
    if not scan_map:
        base_result["General Log"] = f"[ERROR] No scans defined for OS: {os_type}"
        return base_result

    valid_scans = [scan for scan in selected_scans if scan in scan_map]
    if not valid_scans:
        base_result["General Log"] = "[ERROR] No valid scans selected."
        return base_result

    base_result["General Log"] = (
        f"[INFO] Using analysis profile: {os_type}\n"
        f"[INFO] Selected scans: {', '.join(valid_scans)}\n"
        f"[INFO] Starting memory analysis...\n"
    )

    total = len(valid_scans)
    current = 0

    for scan_name in valid_scans:
        current += 1
        plugin = scan_map[scan_name]["plugin"]

        if log_callback:
            log_callback(f"[INFO] Running scan: {scan_name} ({plugin})")

        try:
            env = os.environ.copy()
            env["PYTHONIOENCODING"] = "utf-8"
            env["PYTHONUTF8"] = "1"

            result = subprocess.run(
                [sys.executable, "-X", "utf8", VOL_PATH, "-f", dump_path, plugin],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=env
            )

            output_parts = []
            stdout_clean = result.stdout.strip()

            if stdout_clean:
                lines = [line for line in stdout_clean.splitlines() if line.strip()]
                if len(lines) <= 3:
                    output_parts.append(f"[INFO] No significant results found for {scan_name}.")
                    output_parts.append(result.stdout)
                else:
                    output_parts.append(result.stdout)
            else:
                output_parts.append(f"[INFO] No significant results found for {scan_name}.")

            if result.stderr.strip():
                output_parts.append(f"[STDERR]\n{result.stderr}")

            final_output = "\n".join(output_parts).strip()
            base_result[scan_name] = final_output
            base_result["General Log"] += f"[INFO] {scan_name} analysis complete.\n"

            output_file = os.path.join(
                RESULTS_DIR,
                f"{scan_name.lower().replace(' ', '_')}.txt"
            )
            with open(output_file, "w", encoding="utf-8", errors="replace") as f:
                f.write(final_output)

        except Exception as e:
            base_result[scan_name] = f"[ERROR] Failed running {plugin}: {e}"
            base_result["General Log"] += f"[ERROR] {scan_name} analysis failed.\n"

        if progress_callback:
            percent = 15 + int((current / total) * 85)
            progress_callback(percent)

    base_result["Suspicious Findings"] = build_suspicious_summary(base_result, os_type)
    base_result["General Log"] += "[INFO] Analysis complete"
    return base_result


def extract_indicators_from_results(results: dict) -> dict:
    indicators = {
        "hashes": set(),
        "ips": set(),
        "domains": set()
    }

    network_text = results.get("Network Connections", "")
    if network_text:
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, network_text)
        for ip in ips:
            try:
                ipaddress.ip_address(ip)
                if ip not in ("0.0.0.0", "127.0.0.1", "255.255.255.255"):
                    indicators["ips"].add(ip)
            except ValueError:
                pass

    cmdline_text = results.get("Command Line", "") + "\n" + results.get("Command History", "")
    if cmdline_text:
        url_pattern = r'https?://[^\s<>"\'\)]+'
        urls = re.findall(url_pattern, cmdline_text)
        for url in urls:
            domain_match = re.search(r'://([^/:]+)', url)
            if domain_match:
                domain = domain_match.group(1)
                if domain and not domain.replace(".", "").isdigit():
                    indicators["domains"].add(domain.lower())

    hash_pattern = r'\b[a-fA-F0-9]{32}\b'
    for key in ["Processes", "DLL List", "File Artifacts"]:
        text = results.get(key, "")
        hashes = re.findall(hash_pattern, text)
        for h in hashes:
            if h.upper() != "0" * len(h):
                indicators["hashes"].add(h.upper())

    return {
        "hashes": list(indicators["hashes"]),
        "ips": list(indicators["ips"]),
        "domains": list(indicators["domains"])
    }


def enrich_findings_with_ti(results: dict) -> dict:
    try:
        from threat_intel import get_engine, LookupMode, RiskLevel

        engine = get_engine()

        indicators = extract_indicators_from_results(results)

        if not indicators["hashes"] and not indicators["ips"] and not indicators["domains"]:
            results["General Log"] += "\n[INFO] No indicators found for TI enrichment"
            return results

        results["General Log"] += "\n[INFO] Enriching findings with threat intelligence..."
        results["General Log"] += f"[INFO] Providers available: {', '.join(engine.get_enabled_providers())}"

        enrichment = engine.enrich_findings(indicators, mode=LookupMode.CACHE_FIRST)

        ti_findings = []
        for finding in enrichment.findings:
            risk_icon = {
                RiskLevel.CRITICAL: "[CRITICAL]",
                RiskLevel.HIGH: "[HIGH]",
                RiskLevel.MEDIUM: "[MEDIUM]",
                RiskLevel.LOW: "[LOW]",
                RiskLevel.TRUSTED: "[TRUSTED]",
                RiskLevel.UNKNOWN: "[UNKNOWN]"
            }.get(finding.risk_score, "[UNKNOWN]")

            providers = ", ".join(finding.providers_checked) if finding.providers_checked else "Local"

            if finding.local_heuristic_match:
                source = f"Local Heuristic ({finding.local_heuristic_severity})"
            else:
                source = f"TI ({providers})"

            ti_findings.append(
                f"{risk_icon} {finding.original_value} | Source: {source} | Confidence: {finding.confidence}%"
            )

        if ti_findings:
            results["Threat Intelligence"] = "\n".join(ti_findings)

            risk_level, confidence = engine.get_unified_risk_score(enrichment.findings)
            results["General Log"] += f"\n[INFO] TI Risk Score: {risk_level.value} ({confidence}% confidence)"
            results["General Log"] += f"[INFO] Malicious IOCs found: {enrichment.stats.get('malicious_found', 0)}"
            results["General Log"] += f"[INFO] Cache hits: {enrichment.stats.get('cached_hits', 0)}"

    except ImportError:
        results["General Log"] += "\n[INFO] Threat intelligence module not available"
    except Exception as e:
        results["General Log"] += f"\n[WARNING] TI enrichment failed: {e}"

    return results


def run_advanced_volatility_command(dump_path, os_type, command_text):
    if not os.path.exists(dump_path):
        return "[ERROR] Memory dump file not found."

    if not command_text.strip():
        return "[ERROR] No advanced command entered."

    if os_type == "Auto-detect":
        detected_os = detect_dump_os(dump_path)
        if not detected_os:
            return "[ERROR] Could not determine dump OS automatically."
        os_type = detected_os

    try:
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONUTF8"] = "1"

        command_text = command_text.replace("&&", ";").replace("\n", ";")
        command_parts = [cmd.strip() for cmd in command_text.split(";") if cmd.strip()]

        all_outputs = []

        for cmd_text in command_parts:
            parts = shlex.split(cmd_text)
            full_command = [sys.executable, "-X", "utf8", VOL_PATH, "-f", dump_path] + parts

            result = subprocess.run(
                full_command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=env
            )

            output_parts = []
            if result.stdout.strip():
                output_parts.append(result.stdout)
            if result.stderr.strip():
                output_parts.append(result.stderr)
            
            if output_parts:
                all_outputs.append({
                    "command": " ".join(parts),
                    "output": "\n".join(output_parts)
                })

        return all_outputs

    except Exception as e:
        return [{"command": "error", "output": f"[ERROR] Failed to run advanced command: {e}"}]