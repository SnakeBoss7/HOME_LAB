
import requests, base64
import json

invoke_url = "https://integrate.api.nvidia.com/v1/chat/completions"
stream = False


headers = {
  "Authorization": "Bearer nvapi-<api>",
  "Accept": "text/event-stream" if stream else "application/json"
}

user_prompt = r"""
    Please analyze this event:

    ### RAW SPLUNK TELEMETRY ###
   {'app': 'search', 'owner': 'insaen', 'result_id': '0', 'results_file': '/opt/splunk/var/run/splunk/dispatch/rt_scheduler__insaen__search__RMD53683e10bdf5282a0_at_1764476753_2.0/per_result_alert/tmp_0.csv.gz', 'results_link': 'http://pop-os:8000/app/search/search?q=%7Cloadjob%20rt_scheduler__insaen__search__RMD53683e10bdf5282a0_at_1764476753_2.0%20%7C%20head%201%20%7C%20tail%201&earliest=0&latest=now', 'search_uri': '/servicesNS/insaen/search/saved/searches/LSASS+ACCESS', 'server_host': 'pop-os', 'server_uri': 'https://127.0.0.1:8089', 'session_key': 'c7TQXmKFfC7p7IVFfjEwRl1WF2HB^wzueF7I^1L8Xzd2qlSRDSpauV0Uo_clnctWWWcNxXPXrDlKQCaKfbB8gvvxwU6ZYQ^rUooqx6ich8B2o74LQnpSdBxcbj__z1P5ghbEPWOpbSiInC', 'sid': 'rt_scheduler__insaen__search__RMD53683e10bdf5282a0_at_1764476753_2.0', 'search_name': 'LSASS ACCESS', 'configuration': {}, 'result': {'CallTrace': 'C:\\Windows\\SYSTEM32\\ntdll.dll+9d524|C:\\Windows\\System32\\KERNELBASE.dll+308ee|C:\\Windows\\assembly\\NativeImages_v4.0.30319_64\\System\\4fb9160b27f2daa1ec55050bde519fcc\\System.ni.dll+381d10|C:\\Windows\\assembly\\NativeImages_v4.0.30319_64\\System\\4fb9160b27f2daa1ec55050bde519fcc\\System.ni.dll+2fa12e|C:\\Windows\\assembly\\NativeImages_v4.0.30319_64\\System\\4fb9160b27f2daa1ec55050bde519fcc\\System.ni.dll+2f8cd5|C:\\Windows\\assembly\\NativeImages_v4.0.30319_64\\System\\4fb9160b27f2daa1ec55050bde519fcc\\System.ni.dll+2c3b1e|C:\\Windows\\assembly\\NativeImages_v4.0.30319_64\\System\\4fb9160b27f2daa1ec55050bde519fcc\\System.ni.dll+2c01f5|UNKNOWN(00007FFF4EE12F86)', 'ComputerName': 'DESKTOP-J8TIDPQ', 'EventCode': '10', 'EventType': '4', 'GrantedAccess': '0x1F3FFF', 'Keywords': 'None', 'LogName': 'Microsoft-Windows-Sysmon/Operational', 'Message': 'Process accessed:\nRuleName: T1003.001_LSASS_Access\nUtcTime: 2025-11-30 04:28:33.825\nSourceProcessGUID: {f30977a8-c7f0-692b-c701-000000002b00}\nSourceProcessId: 7996\nSourceThreadId: 5468\nSourceImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\nTargetProcessGUID: {f30977a8-c47d-692b-0c00-000000002b00}\nTargetProcessId: 672\nTargetImage: C:\\Windows\\system32\\lsass.exe\nGrantedAccess: 0x1F3FFF\nCallTrace: C:\\Windows\\SYSTEM32\\ntdll.dll+9d524|C:\\Windows\\System32\\KERNELBASE.dll+308ee|C:\\Windows\\assembly\\NativeImages_v4.0.30319_64\\System\\4fb9160b27f2daa1ec55050bde519fcc\\System.ni.dll+381d10|C:\\Windows\\assembly\\NativeImages_v4.0.30319_64\\System\\4fb9160b27f2daa1ec55050bde519fcc\\System.ni.dll+2fa12e|C:\\Windows\\assembly\\NativeImages_v4.0.30319_64\\System\\4fb9160b27f2daa1ec55050bde519fcc\\System.ni.dll+2f8cd5|C:\\Windows\\assembly\\NativeImages_v4.0.30319_64\\System\\4fb9160b27f2daa1ec55050bde519fcc\\System.ni.dll+2c3b1e|C:\\Windows\\assembly\\NativeImages_v4.0.30319_64\\System\\4fb9160b27f2daa1ec55050bde519fcc\\System.ni.dll+2c01f5|UNKNOWN(00007FFF4EE12F86)\nSourceUser: DESKTOP-J8TIDPQ\\INSAEN\nTargetUser: NT AUTHORITY\\SYSTEM', 'OpCode': 'Info', 'RecordNumber': '36288', 'RuleName': 'T1003.001_LSASS_Access', 'Sid': 'S-1-5-18', 'SidType': '0', 'SourceImage': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', 'SourceName': 'Microsoft-Windows-Sysmon', 'SourceProcessGUID': '{f30977a8-c7f0-692b-c701-000000002b00}', 'SourceProcessId': '7996', 'SourceThreadId': '5468', 'SourceUser': 'DESKTOP-J8TIDPQ\\INSAEN', 'TargetImage': 'C:\\Windows\\system32\\lsass.exe', 'TargetProcessGUID': '{f30977a8-c47d-692b-0c00-000000002b00}', 'TargetProcessId': '672', 'TargetUser': 'NT AUTHORITY\\SYSTEM', 'TaskCategory': 'Process accessed (rule: ProcessAccess)', 'Type': 'Information', 'User': 'NOT_TRANSLATED', 'UtcTime': '2025-11-30 04:28:33.825', '_confstr': 'source::WinEventLog:Microsoft-Windows-Sysmon/Operational|host::DESKTOP-J8TIDPQ|Win10', '_eventtype_color': '', '_indextime': '1764476915', '_pre_msg': '11/30/2025 09:58:33.841 AM\nLogName=Microsoft-Windows-Sysmon/Operational\nEventCode=10\nEventType=4\nComputerName=DESKTOP-J8TIDPQ\nUser=NOT_TRANSLATED\nSid=S-1-5-18\nSidType=0\nSourceName=Microsoft-Windows-Sysmon\nType=Information\nRecordNumber=36288\nKeywords=None\nTaskCategory=Process accessed (rule: ProcessAccess)\nOpCode=Info', '_raw': '11/30/2025 09:58:33.841 AM\nLogName=Microsoft-Windows-Sysmon/Operational\nEventCode=10\nEventType=4\nComputerName=DESKTOP-J8TIDPQ\nUser=NOT_TRANSLATED\nSid=S-1-5-18\nSidType=0\nSourceName=Microsoft-Windows-Sysmon\nType=Information\nRecordNumber=36288\nKeywords=None\nTaskCategory=Process accessed (rule: ProcessAccess)\nOpCode=Info\nMessage=Process accessed:\nRuleName: T1003.001_LSASS_Access\nUtcTime: 2025-11-30 04:28:33.825\nSourceProcessGUID: {f30977a8-c7f0-692b-c701-000000002b00}\nSourceProcessId: 7996\nSourceThreadId: 5468\nSourceImage: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\nTargetProcessGUID: {f30977a8-c47d-692b-0c00-000000002b00}\nTargetProcessId: 672\nTargetImage: C:\\Windows\\system32\\lsass.exe\nGrantedAccess: 0x1F3FFF\nCallTrace: C:\\Windows\\SYSTEM32\\ntdll.dll+9d524|C:\\Windows\\System32\\KERNELBASE.dll+308ee|C:\\Windows\\assembly\\NativeImages_v4.0.30319_64\\System\\4fb9160b27f2daa1ec55050bde519fcc\\System.ni.dll+381d10|C:\\Windows\\assembly\\NativeImages_v4.0.30319_64\\System\\4fb9160b27f2daa1ec55050bde519fcc\\System.ni.dll+2fa12e|C:\\Windows\\assembly\\NativeImages_v4.0.30319_64\\System\\4fb9160b27f2daa1ec55050bde519fcc\\System.ni.dll+2f8cd5|C:\\Windows\\assembly\\NativeImages_v4.0.30319_64\\System\\4fb9160b27f2daa1ec55050bde519fcc\\System.ni.dll+2c3b1e|C:\\Windows\\assembly\\NativeImages_v4.0.30319_64\\System\\4fb9160b27f2daa1ec55050bde519fcc\\System.ni.dll+2c01f5|UNKNOWN(00007FFF4EE12F86)\nSourceUser: DESKTOP-J8TIDPQ\\INSAEN\nTargetUser: NT AUTHORITY\\SYSTEM', '_serial': '0', '_si': ['pop-os', 'sysmon'], '_sourcetype': 'Win10', '_subsecond': '.841', '_time': '1764476913.841', 'eventtype': '', 'host': 'DESKTOP-J8TIDPQ', 'index': 'sysmon', 'linecount': '', 'punct': '//_::._=--/===-==---==--====__(:_)==_:\\r:_.\\r:_--_::', 'source': 'WinEventLog:Microsoft-Windows-Sysmon/Operational', 'sourcetype': 'Win10', 'splunk_server': 'pop-os'}}

    ### ENRICHMENT DATA ###
    - VirusTotal: not available
    - Shodan/AbuseIPDB: not available
    """

# parse json
def parse_llm_response(response):
    res = response['choices'][0]['message']['content'].strip()
    try:
        return json.loads(res)
    except Exception as e:
        debug_log("Failed to parse LLM response", str(e))
        return None

system_prompt = """
### ROLE ###
You are a Tier 3 SOC Analyst. Your task is to analyze security alerts and output structured data for automation.

### STRICT OUTPUT FORMAT ###
You must output ONLY valid JSON. Do not include markdown formatting (like ```json), do not include introductory text, and do not include explanations outside the JSON object.

Use this exact schema:
{
    "summary": "1 sentence executive summary of the event",
    "severity": "CRITICAL",  // Options: CRITICAL, HIGH, MEDIUM, LOW, FALSE_POSITIVE
    "confidence_score": 90,  // Integer 0-100
    "technical_analysis": {
        "actor": "User or Process Name",
        "action": "What happened",
        "mitre_technique": "T-ID",
        "flags": ["List", "Of", "Suspicious", "Indicators"]
    },
    "recommended_actions": [
        "Action 1",
        "Action 2",
        "Action 3"
    ]
}

### ANALYSIS RULES ###
1. If 'GrantedAccess' is '0x1F3FFF', score as HIGH/CRITICAL (Credential Dumping).
2. If SourceImage is 'WerFault.exe' or 'MsMpEng.exe', score as FALSE_POSITIVE (System activity).
3. If Enrichment data is missing, rely solely on the telemetry.
"""


payload = {
  "model": "meta/llama-4-maverick-17b-128e-instruct",
  "messages": [{"role":"system","content":system_prompt+"\n\nDetailed thinking on."},{"role":"user","content":json.dumps(user_prompt)}],
  "max_tokens": 512,
  "temperature": 0.6,
  "top_p": 0.95,
  "frequency_penalty": 0.00,
  "presence_penalty": 0.00,
  "stream": stream
}

response = requests.post(invoke_url, headers=headers, json=payload)
res = response.json()
if stream:
    for line in response.iter_lines():
        if line:
            print(line.decode("utf-8"))
else:
    print(parse_llm_response(res))
