import os 
import json
import sys
from jira import JIRA
from datetime import datetime

# Configuration
JIRA_SERVER = 'http://localhost:8080'
JIRA_USER = 'insaen'
JIRA_PASS = 'RAHUL12005'
PROJECT_KEY = 'SOC'
VT_API='<api_key>'



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
        # Fallback to Basic Auth
        jira = JIRA(options=jira_options, basic_auth=(JIRA_USER, JIRA_PASS))
        return jira
    except Exception as e:
        debug_log("Jira Connection Failed", str(e))
        print(f"Error connecting to Jira: {e}")
        sys.exit(1)

# ticket creation
def ticket_creation(jira, issue_type):
    try:
        ticket = jira.create_issue(
            project=PROJECT_KEY,
            summary='Test Ticket from Python SOAR',
            description='This is a test ticket created by the automation script.',
            issuetype={'name': issue_type}
        )
        return ticket
    except Exception as e:
        debug_log("Ticket Creation Failed", str(e))
        print(f"Error creating ticket: {e}")
        return None

# Get payload from stdin Splunk
def get_payload():
    try:
        payload = sys.stdin.read()
        return json.loads(payload)
    except Exception as e:
        debug_log("Failed to read payload", str(e))
        return None


def main():
    # jira connection
    debug_log("jira connection started", "nothing")
    jira = jira_conn()
    debug_log("jira connection success", jira)
   
    # get payload from stdin
    debug_log("get payload started", "nothing")
    payload = get_payload()
    debug_log("get payload success", payload)
    debug_log("Check json wroking", payload['result'])
    
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