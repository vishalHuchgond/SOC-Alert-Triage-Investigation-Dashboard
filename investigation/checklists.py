"""Per-detection triage checklists shown in the investigation view."""

CHECKLISTS: dict[str, list[str]] = {
    "brute_force": [
        "Is the source IP internal (misconfigured service) or external?",
        "Did any successful login follow the failures? (check success_after_failures alerts)",
        "Which accounts were targeted - are any privileged or service accounts?",
        "Is the source a known vulnerability scanner? If yes, allowlist it.",
        "Check geo/IP reputation and whether the source is on the watchlist.",
    ],
    "password_spray": [
        "How many distinct accounts were targeted?",
        "Were the attempts spread out to evade lockout (low-and-slow)?",
        "Did any targeted account later log in successfully from the same source?",
        "Check for impossible-travel against VPN/SSO logs for targeted users.",
    ],
    "multiple_failed_logins": [
        "Is this a single user forgetting a password, or an attack against the account?",
        "Check the source IPs - one source suggests targeting; many sources suggest credential stuffing.",
        "Verify whether the account has a password reset workflow triggered.",
    ],
    "success_after_failures": [
        "Treat as high priority: this may be a confirmed compromise.",
        "Identify the successful account and session (logon type, host).",
        "Check activity after login: new processes, tasks, accounts created.",
        "Contain: consider resetting the account credential and reviewing sessions.",
    ],
    "suspicious_powershell": [
        "Retrieve the full script block (4104) and decoded commands.",
        "Identify the parent process that launched PowerShell.",
        "Check network connections made by the powershell.exe process.",
        "Was this an admin tool or software deployment (SCCM/Intune)?",
    ],
    "encoded_powershell": [
        "Review the decoded command in full - what does it actually do?",
        "Check for download cradles, AMSI bypasses, or reflection loads in the payload.",
        "Extract and enrich all URLs, IPs, and hashes from the decoded command.",
    ],
    "command_shell_execution": [
        "Which application spawned the shell (Office macro, browser exploit, web shell)?",
        "If w3wp.exe -> cmd: treat as possible web shell; review web logs for the request.",
        "Check the command line and working directory of the shell process.",
    ],
    "port_scanning": [
        "Is the source an approved vulnerability scanner? If yes, allowlist it.",
        "Which ports and targets were hit - infrastructure or user subnets?",
        "Did any connection succeed after the scan (follow-on movement)?",
    ],
    "suspicious_process_execution": [
        "What command-line arguments were passed to the LOLBin?",
        "certutil with -urlcache/-decode, mshta with http: strong malicious indicators.",
        "Check the file involved (hash it, look it up) and its origin.",
    ],
    "account_creation": [
        "Who created the account, and from where (4624 context)?",
        "Was the account added to privileged groups (4728/4732/4756)?",
        "If unexpected: disable the account and reset the creator credentials.",
    ],
    "scheduled_task_creation": [
        "What command does the task run and under which account?",
        "Who created it, and is that identity expected to create tasks?",
        "Check the task's run history and network activity at trigger time.",
    ],
    "security_log_clearing": [
        "Which account cleared the log (1102 subject)?",
        "What happened on the host immediately BEFORE the clearing?",
        "Preserve remaining logs and consider this a confirmed incident.",
    ],
}


def checklist_for(detection_name: str) -> list[str]:
    return CHECKLISTS.get(detection_name, [
        "Identify the source and target of the activity.",
        "Determine whether the activity matches expected admin or service behavior.",
        "Check related alerts and correlation groups for wider context.",
    ])
