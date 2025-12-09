import os
import sys
import json
import datetime
import requests
import urllib3

# --- PREREQUESTIES ---
#JIRA
JIRA_SERVER="http://localhost:8080"
JIRA_USER="insaen"
PROJECT_KEY="SOC"
#VIRUS TOTAL
VT_URL='https://www.virustotal.com/api/v3/files/'

# Ensure your vendor path is included which contains all the libraries
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vendor'))

# Disable SSL warnings since we are hitting localhost:8089 with verify=False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from jira import JIRA

# --- DEBUG FUNCION ---

def debug_log(mess, data):
    """Logs messages to stdout and a debug file, ensuring no truncation."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    message = f"[{timestamp}] message:{mess} \nand data:{data}\n"
    try:
        print(message)
        with open("/tmp/soar_debug.log", "a") as f:
            f.write(message)
    except Exception as e:
        sys.stderr.write(f"Error writing to log: {e}\n")

# --- PAYLOAD FUNCION ---
def get_payload():
    """Reads the raw JSON payload from stdin."""
    try:
        data = sys.stdin.read()
        debug_log("payload raw data length", len(data))
        return data
    except Exception as e:
        debug_log("no payloads found", "no payload")
        return None

# --- 3. SECURE RETRIEVAL FUNCTION (REST API METHOD) ---

def get_secure_password(session_key, realm, username):
    """Retrieves an encrypted password/secret using Splunk's REST API."""
    
    API_OWNER = "nobody"
    API_APP = "soar_mini"
    
    # FIXED: The correct format is {realm}:{username}: not {username}:{realm}
    credential_id = f"{realm}:{username}:"
    credential_endpoint = f"/servicesNS/{API_OWNER}/{API_APP}/storage/passwords/{credential_id}"
    url = f"https://localhost:8089{credential_endpoint}?output_mode=json"
    
    debug_log("Attempting URL", url)
    
    headers = {
        'Authorization': f'Splunk {session_key}',
        'Accept': 'application/json' 
    }
    
    try:
        # Make the secure HTTP request
        response = requests.get(url, headers=headers, verify=False)   
        debug_log("Response Status Code", response.status_code)
        debug_log("Response Headers", dict(response.headers))
        debug_log("Response Text (first 500 chars)", response.text[:500])
        
        response.raise_for_status()
        
        # Parse the JSON response
        data = response.json()
        
        # The password is located inside the content block of the entry list
        password = data['entry'][0]['content']['clear_password']
        
        return password

    except requests.exceptions.RequestException as e:
        debug_log("REST API Error (Connection/Auth)", str(e))
        
        # FALLBACK: If direct access fails, try searching through all credentials
        debug_log("Attempting fallback", "Searching all credentials")
        return get_password_fallback(session_key, realm, username, API_OWNER, API_APP)
        
    except (IndexError, KeyError) as e:
        debug_log("REST API Error (Parsing or Missing Field)", f"Error: {e}")
        return None
    except ValueError as e:
        debug_log("JSON Parse Error", f"Could not parse response as JSON: {e}")
        # Try fallback
        return get_password_fallback(session_key, realm, username, API_OWNER, API_APP)
    except Exception as e:
        debug_log("Unexpected Error in REST call", str(e))
        return None


def get_password_fallback(session_key, realm, username, owner, app):
    """
    Fallback method: Get all passwords and search for the matching one.
    This is useful when the exact credential ID format is unclear.
    """
    url = f"https://localhost:8089/servicesNS/{owner}/{app}/storage/passwords?output_mode=json"
    
    headers = {
        'Authorization': f'Splunk {session_key}',
        'Accept': 'application/json'
    }
    
    try:
        response = requests.get(url, headers=headers, verify=False)
        
        debug_log("Fallback Response Status", response.status_code)
        debug_log("Fallback Response Text (first 1000 chars)", response.text[:1000])
        
        response.raise_for_status()
        
        data = response.json()
        
        # Search through all credentials
        for entry in data.get('entry', []):
            content = entry.get('content', {})
            entry_realm = content.get('realm')
            entry_username = content.get('username')
            
            debug_log("Found credential", f"realm={entry_realm}, username={entry_username}")
            
            # Match both realm and username
            if entry_realm == realm and entry_username == username:
                password = content.get('clear_password')
                debug_log("Match found!", f"Retrieved password for {username}@{realm}")
                return password
        
        debug_log("No match found", f"No credential found for {username}@{realm}")
        return None
        
    except Exception as e:
        debug_log("Fallback method failed", str(e))
        return None

# --- AI Functions ---

invoke_url = "https://integrate.api.nvidia.com/v1/chat/completions"
stream = False

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
def ai_res(tel_payload,key):
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
    headers = {
    "Authorization": "Bearer " + key,
    "Accept": "text/event-stream" if stream else "application/json"
    }

    response = requests.post(invoke_url, headers=headers, json=payload)
    res = parse_llm_response(response.json())
    print(res)
    return res

# parse json from llm response
def parse_llm_response(response):
    try:
        res = response['choices'][0]['message']['content'].strip()
        return json.loads(res)
    except Exception as e:
        debug_log("Failed to parse LLM response", f"Error: {e}, Raw Response: {response}")
        return None


# --- JIRA ---
# jira connection
def jira_conn(password):
    jira_options = {'server': JIRA_SERVER}
    try:
        # Basic Auth
        jira = JIRA(options=jira_options, basic_auth=(JIRA_USER, password))
        return jira
    except Exception as e:
        debug_log("Jira Connection Failed", str(e))
        print(f"Error connecting to Jira: {e}")
        sys.exit(1)

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

# --- MAIN ---
def main():
    # --- PAYLOAD RETRIEVAL ---
    raw_data = get_payload()
    
    if not raw_data:
        debug_log("No payload found", "No payload found")
        sys.exit(1)
    # --- EXTRACT SESSION KEY ---    
    try:
        data = json.loads(raw_data)
        
        session_key = data.get('session_key')
        alert_owner = data.get('owner')
        
        if not session_key or not alert_owner:
            debug_log("Fatal Error", "Session key or owner missing from payload.")
            sys.exit(1)

    except Exception as e:
        debug_log("JSON Parsing Error", str(e))
        sys.exit(1)

    debug_log("session_key", session_key)
    
    # Credentials to look up
    #JIRA
    realm1 = "soar_jira_credentials"
    username1 = "insaen"

    #NVIDIA
    realm2 = "soar_nvidia_credentials"
    username2 = "nv"
    
    #VIRUS_TOTAL
    realm3 = "soar_virusT_credentials"
    username3 = "vt"

    # 4. GET PASSWORD using REST API
    password_JIRA = get_secure_password(session_key, realm1, username1)
    password_NV = get_secure_password(session_key, realm2, username2)
    password_VT = get_secure_password(session_key, realm3, username3)

    # Getting ai response
    ai_data = ai_res(data,password_NV)
    debug_log("ai_response",ai_data)
    jira = jira_conn(password_JIRA)
    if jira:
        debug_log("connection SUccess",jira)
    else:
        debug_log("connection fail",jira)

    ticket = ticket_creation(jira,"Incident" ,ai_data)
    if ticket:
        debug_log("ticket created",ticket)
    else:
        debug_log("ticket creation fail",ticket)
    # debug_log("password_VT", password_VT)
    # debug_log("password_NV", password_NV)
    # debug_log("password_JIRA", password_JIRA)

    
if __name__ == "__main__":
    main()