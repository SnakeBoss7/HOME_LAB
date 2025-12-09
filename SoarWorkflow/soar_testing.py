import os 
import json
import sys
from jira import JIRA
from datetime import datetime
import requests
from dotenv import load_dotenv
load_dotenv()

# testing command
# echo '{"result": {"host": "TEST-HOST", "message": "Test Message", "EventCode": "4624", "EventType": "0", "RuleName": "Test Rule", "GrantedAccess": "0x1F3FFF", "_time": "2025-11-30T10:00:00"}}' | python3 MINI-SOAR-PY/alert_script.py

# jira Configuration 
JIRA_SERVER = os.getenv("JIRA_SERVER")
JIRA_USER = os.getenv("JIRA_USER")
JIRA_PASS = os.getenv("JIRA_PASS")
PROJECT_KEY = os.getenv("PROJECT_KEY")


# Ai configuration
invoke_url = "https://integrate.api.nvidia.com/v1/chat/completions"
nv_api=os.getenv('NV_API');
stream = False
headers = {
  "Authorization": "Bearer "+nv_api,
  "Accept": "text/event-stream" if stream else "application/json"
}

user_boilerplate_prompt = r"""
    Please analyze this event:

    ### RAW SPLUNK TELEMETRY ###
    {payload}
    ### ENRICHMENT DATA ###
    - VirusTotal: not available
    - Shodan/AbuseIPDB: not available
    """

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
    "description":"Full description of the event",
    "labels": ["Lsass","Credential"] #one word,
    "technical_analysis": {
        "actor": "User or Process Name",
        "action": "What happened",
        "mitre_technique": "T-ID",
    
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


# enrichment configuration
VT_API= os.getenv("VT_API")
VT_URL='https://www.virustotal.com/api/v3/files/'


# parse json from llm response
def parse_llm_response(response):
    try:
        res = response['choices'][0]['message']['content'].strip()
        return json.loads(res)
    except Exception as e:
        debug_log("Failed to parse LLM response", f"Error: {e}, Raw Response: {response.text}")
        return None


# debug log creation
def debug_log(msg, data):
    timestamp = datetime.now()
    log_entry = f"[{timestamp}] message:{msg}\n  data/args:{data}\n"
    try:
        # Using /tmp  for debug logging
        print("Debug Log:", log_entry)
        with open("/tmp/soar_debug.log", "a") as f:
            f.write(log_entry)
    except Exception as e:
        print(f"Failed to write to log: {e}")

# jira connection
def jira_conn():
    jira_options = {'server': JIRA_SERVER}
    try:
        # Basic Auth
        jira = JIRA(options=jira_options, basic_auth=(JIRA_USER, JIRA_PASS))
        return jira
    except Exception as e:
        debug_log("Jira Connection Failed", str(e))
        print(f"Error connecting to Jira: {e}")
        sys.exit(1)

def get_epic_key(jira, epic_name):
    jql = f'issuetype = Epic AND "Epic Name" ~ "{epic_name}"'
    issues = jira.search_issues(jql)

    if issues:
        return issues[0].key  # Example: "PROJ-12"
    return None
# ticket creation
def ticket_creation(jira, issue_type,ticket_payload):
    try:
        ticket = jira.create_issue(
            project={'key': PROJECT_KEY},
            summary=ticket_payload['summary'],
            labels=ticket_payload['labels'],
            description=str(ticket_payload['description']),
            customfield_10100="SOC-1",
            priority={'name': 'High'} if ticket_payload['severity'] in ['CRITICAL', 'HIGH'] else {'name': 'Medium'},
            customfield_10301=str(ticket_payload['technical_analysis']),
            customfield_10202=ticket_payload['technical_analysis'].get('mitre_technique', 'Unknown'),
            customfield_10300=str(ticket_payload['recommended_actions']),
            issuetype={'name': issue_type}
        )
        return ticket
    except Exception as e:
        debug_log("Ticket Creation Failed", str(e))
        print(f"Error creating ticket: {e}")
        return None

def virus_total_enrichment(hash):
    print(hash)
    sha256 = hash.split(",")[0].split("=")[1]
    print(sha256)
    try:
        url = f"{VT_URL}/{sha256}"
        headers = {
            "x-apikey": VT_API
        }
        response = requests.get(url,headers=headers)
        print("response of virsusT \n")
        data = response.json()
        # print(data["data"])
        print(json.dumps(data, indent=4))


    except Exception as e:
        debug_log("VirusTotal Enrichment Failed", str(e))
        print(f"Error enriching with VirusTotal: {e}")
        return None
# AI encrichment

def ai_res(tel_payload):
    user_prompt =  user_boilerplate_prompt.replace("{payload}", json.dumps(tel_payload['result']))
    payload = {
        "model": "meta/llama-4-maverick-17b-128e-instruct",
        "messages": [{"role":"system","content":system_prompt+"\n\nDetailed thinking on."},{"role":"user","content":user_prompt}],
        "max_tokens": 512,
        "temperature": 0.6,
        "top_p": 0.95,
        "frequency_penalty": 0.00,
        "presence_penalty": 0.00,
        "stream": stream
    }
    response = requests.post(invoke_url, headers=headers, json=payload)
    res = parse_llm_response(response.json())
    print(res)
    return res

    
# Get payload from stdin Splunk
def get_payload():
    try:
        payload = sys.stdin.read()
        debug_log("splunk payload", payload)
        return json.loads(payload)
    except Exception as e:
        debug_log("Failed to read payload", str(e))
        return None


def main():
    # jira connection
    debug_log("jira connection started", "nothing")
    jira = jira_conn()
    debug_log("jira connection success", jira)
    for field in jira.issue_types():
        print(field)
    # get payload from stdin
    debug_log("get payload started", "nothing")
    payload = get_payload()

    # ai summary
    final_res = ai_res(tel_payload=payload)
    debug_log("Final response ",final_res)
    
    # enrichment
    # hash = payload['result']['Hashes']
    # virus_total_enrichment(hash)
    # ticket_creation(jira,'Incident',final_res)
    


    # owner = payload['owner']
    # host = payload['result']['host']
    # message = payload['result']['message']
    # eventCode = payload['result']['EventCode']
    # eventType = payload['result']['EventType']
    # RuleName = payload['result']['RuleName']
    # GrantAcess = payload['result']['GrantedAccess']
    # Time = payload['result']['_time']
    
    # # ticket creation
    # print("Creating ticket...")
    # ticket = ticket_creation(jira, 'Task')
        
    # if ticket:
    #     debug_log("Ticket created successfully", ticket.key)
    #     print(f"Success! Ticket created: {ticket.key} ({ticket.permalink()})")
    # else:
    #     print("Failed to create ticket.")

if __name__ == "__main__":
    main()