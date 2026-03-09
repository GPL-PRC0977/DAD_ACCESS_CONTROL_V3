import re
from flask import request, jsonify
import json
import logging
from google.cloud import logging as gcp_logging
import pytz

project_id = "pgc-one-primer-dw"
log_name = "control-center-logs"
app_title = "User Control Center"

ph_timezone = pytz.timezone("Asia/Manila")

local_logger = logging.getLogger("local")
if not local_logger.handlers:
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    local_logger.addHandler(ch)
local_logger.setLevel(logging.INFO)

gcp_logger_client = None
logger = None

gcp_logger_client = gcp_logging.Client(project=project_id)
logger = gcp_logger_client.logger(log_name)

SQLI_PATTERNS = re.compile(
    r"\b(union\s+select|select\s+.*from|insert\s+into|drop\s+table|exec\s|xp_cmdshell|declare\s|waitfor\s+delay|sleep\(|and\s+1=1|--|#|;)\b",
    re.IGNORECASE
)

XSS_PATTERNS = re.compile(
    r"(<script[^>]*?>.*?</script>|<[^>]*?\bon\w+\s*=|javascript:|(eval|document\.)\s*\()",
    re.IGNORECASE | re.DOTALL
)

CMD_INJECTION_PATTERNS = re.compile(
    r"(\{1,2}|\|{1,2}|;|\`|\$\(|\$\{|\|bash|\%0a|\%0d)",
    re.IGNORECASE
)

PATH_TRAVERSAL_PATTERNS = re.compile(
    r"(\.\./|\.\.\\|/etc/passwd|/proc/self/environ)",
    re.IGNORECASE
)

SECURITY_CHECKS = [
    ("SQL_INJECTION", SQLI_PATTERNS),
    ("XSS", XSS_PATTERNS),
    ("COMMAND_INJECTION", CMD_INJECTION_PATTERNS),
    ("PATH_TRAVERSAL", PATH_TRAVERSAL_PATTERNS),
]


def rasp_check_and_block():
    """
    Analyzes the incoming request against a suite of industry-standard patterns.
    If a threat is detected, it logs a structured JSON object to stdout 
    for Google Cloud Logs Explorer and returns a structured 403 Response.
    """

    # Data sources to check (URL params, form data, JSON body)
    data_sources = []

    # Add URL arguments and form data
    if request.values:
        data_sources.extend(request.values.items())

    # Add JSON body data if present
    if request.is_json:
        try:
            # For JSON, we check the string representation of the data
            payload_str = str(request.get_json())
            data_sources.append(("JSON_PAYLOAD", payload_str))
        except Exception:
            pass  # Ignore malformed JSON

    # Iterate over all data sources and all security checks
    for source_key, source_value in data_sources:
        # Cast value to string for consistent regex checking
        value_str = str(source_value)

        for attack_name, pattern in SECURITY_CHECKS:
            if pattern.search(value_str):
                # Threat Detected!

                # Capture the specific matched string for better forensic data
                matched_pattern = pattern.search(value_str).group(0)

                # ----------------------------------------------------------------
                # STRUCTURED LOGGING FOR GOOGLE LOGS EXPLORER (The change)
                # ----------------------------------------------------------------
                log_entry = {
                    # Standard Cloud Logging field (required for severity filter)
                    # "severity": "ERROR",

                    # Custom fields for BigQuery analysis
                    "message": "RASP: Security Incident Blocked",
                    "attack_type": attack_name,
                    "matched_pattern_snip": matched_pattern,
                    "source_input_key": source_key,
                    "request_uri": request.path,
                    "request_method": request.method,
                    "client_ip": request.remote_addr,
                    # Log the first 100 characters of the malicious value for context
                    "input_value_snip": value_str[:100],
                }

                logger.log_text(json.dumps(log_entry), severity="WARNING", labels={
                                "app_title": app_title})

                # Use print() with json.dumps() to write structured JSON to stdout.
                # Cloud Logging will automatically parse this into queryable fields.
                print(json.dumps(log_entry))

                # ----------------------------------------------------------------
                # HTTP RESPONSE TO CLIENT (Unchanged)
                # ----------------------------------------------------------------
                return jsonify({
                    "status": "blocked",
                    "attack_type": attack_name,
                    "matched_string": matched_pattern,
                    "message": "Security threat detected and mitigated by RASP middleware. Incident logged for analysis.",
                    "request_uri": request.path,
                }), 403

    return None  # Request is clean
