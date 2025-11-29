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

# debug log creation
def debug_log(msg, data):
    timestamp = datetime.now()
    log_entry = f"[{timestamp}] {msg}\n {data}\n"
    try:
        with open("/tmp/soar_debug.log", "a") as f:
            f.write(log_entry)
    except Exception as e:
        print(f"Failed to write to log: {e}")
        print(log_entry)

# jira connection
def jira_conn():
    jira_options = {'server': JIRA_SERVER}
    try:
        jira = JIRA(options=jira_options, basic_auth=(JIRA_USER, JIRA_PASS))
        debug_log("Jira Connection Success", str(jira))
        return jira
    except Exception as e:
        debug_log("Jira Connection Failed", str(e))
        print(f"Error connecting to Jira: {e}")
        sys.exit(1)

# ticket creation
def ticket_creation(jira, summary, description, issue_type='Task'):
    try:
        ticket = jira.create_issue(
            project=PROJECT_KEY,
            summary=summary,
            description=description,
            issuetype={'name': issue_type}
        )
        debug_log("Ticket Created", f"Key: {ticket.key}, Link: {ticket.permalink()}")
        return ticket
    except Exception as e:
        debug_log("Ticket Creation Failed", str(e))
        print(f"Error creating ticket: {e}")
        return None

def main():
    debug_log("=== Script Started ===", f"Arguments: {sys.argv}")
    
    # Check for --execute flag
    if len(sys.argv) < 2 or sys.argv[1] != "--execute":
        debug_log("ERROR", "Expected --execute flag")
        sys.stderr.write("ERROR: Expected --execute flag\n")
        sys.exit(1)
    
    try:
        # Read payload from stdin
        debug_log("Reading stdin", "Started")
        raw_payload = sys.stdin.read()
        
        debug_log("STDIN LENGTH", len(raw_payload))
        debug_log("STDIN RAW (first 500 chars)", raw_payload[:500])
        
        if not raw_payload:
            debug_log("ERROR", "No payload received from stdin")
            sys.stderr.write("ERROR: No payload received\n")
            sys.exit(1)
        
        # Parse JSON payload
        payload = json.loads(raw_payload)
        debug_log("Payload parsed successfully", f"Keys: {list(payload.keys())}")
        
        # Extract alert information
        search_name = payload.get('search_name', 'Unknown Alert')
        result = payload.get('result', {})
        results_link = payload.get('results_link', '')
        sid = payload.get('sid', '')
        server_host = payload.get('server_host', '')
        
        debug_log("Alert Details", json.dumps({
            'search_name': search_name,
            'sid': sid,
            'server_host': server_host
        }, indent=2))
        
        debug_log("First Result", json.dumps(result, indent=2))
        
        # Build ticket summary and description
        summary = f"[SOAR Alert] {search_name}"
        
        description = f"""
Security Alert Triggered by Splunk SOAR

Alert Name: {search_name}
Search ID: {sid}
Server: {server_host}
Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Alert Details:
{json.dumps(result, indent=2)}

Splunk Link: {results_link}

--- Automated Ticket Created by SOAR ---
"""
        
        debug_log("Ticket Content Prepared", f"Summary: {summary}")
        
        # Connect to Jira
        print("Connecting to Jira...")
        debug_log("Jira connection started", "Initializing")
        jira = jira_conn()
        
        # Create ticket
        print("Creating ticket...")
        debug_log("Ticket creation started", "Calling Jira API")
        ticket = ticket_creation(jira, summary, description, 'Task')
        
        if ticket:
            debug_log("=== SOAR Action Completed Successfully ===", 
                     f"Ticket: {ticket.key} - {ticket.permalink()}")
            print(f"Success! Ticket created: {ticket.key} ({ticket.permalink()})")
            sys.exit(0)
        else:
            debug_log("ERROR", "Failed to create ticket")
            print("Failed to create ticket.")
            sys.exit(1)
            
    except json.JSONDecodeError as e:
        debug_log("ERROR: Failed to parse JSON", str(e))
        debug_log("Raw data received", raw_payload)
        sys.stderr.write(f"ERROR: Invalid JSON: {str(e)}\n")
        sys.exit(1)
        
    except Exception as e:
        debug_log("ERROR: Unexpected error", str(e))
        import traceback
        debug_log("Traceback", traceback.format_exc())
        sys.stderr.write(f"ERROR: {str(e)}\n")
        sys.exit(1)

if __name__ == "__main__":
    main()
