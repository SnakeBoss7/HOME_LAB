# Jira Setup Guide for Home Lab SOC

This guide will help you set up a Jira environment to act as your ticketing system for security incidents detected by Splunk.

## 1. Account & Instance Setup

1.  **Sign Up**: Go to [Atlassian Jira](https://www.atlassian.com/software/jira) and sign up for the **Free** plan. This is sufficient for a home lab.
2.  **Create Site**: You will be asked to create a site name (e.g., `my-soc-lab.atlassian.net`). This URL is important for your Python script later.

## 2. Project Creation

For a Security Operations Center (SOC) workflow, you want a board that tracks the state of incidents (New -> Investigating -> Resolved).

1.  **Create Project**: Click "Create project".
2.  **Template Selection**:
    *   **Recommended**: Choose **Kanban** (under Software Development). It's simple and visual.
    *   *Alternative*: **Jira Service Management** (ITSM) is more "real-world" for IT tickets but has a steeper learning curve. Stick to Kanban for now.
3.  **Project Details**:
    *   **Name**: `SOC Incidents`
    *   **Key**: `SOC` (This key is crucial. Your tickets will be named `SOC-1`, `SOC-2`, etc.)
    *   **Type**: Team-managed (easier config) or Company-managed (more control). **Team-managed** is fine for a solo lab.

## 3. Configuring Fields (The Data You Need)

By default, Jira gives you a Title and Description. For security alerts, you might want more specific data visible at a glance.

### Standard Fields to Use:
*   **Summary**: This will be your Alert Title (e.g., "Mimikatz Detected on Host-A").
*   **Description**: This is where your **AI Analysis** and raw log details will go.
*   **Priority**: Map your Splunk Alert Severity to this (Critical, High, Medium, Low).
*   **Labels**: Use this for tagging (e.g., `Splunk`, `Sysmon`, `VirusTotal`).

### (Optional) Custom Fields:
If you want to get fancy, you can create custom fields for specific IOCs (Indicators of Compromise), but putting them in the **Description** is usually enough for a starter project.

*   `Source IP`
*   `Malicious Hash`
*   `MITRE Tactic`

## 4. Workflow Statuses

Customize your board columns to match a simplified Incident Response lifecycle:

1.  **To Do** -> Rename to **New Alert** (The script creates tickets here).
2.  **In Progress** -> Rename to **Investigating** (You move it here when you start looking).
3.  **Done** -> Rename to **Closed/False Positive** (When finished).

---

## Next Steps
Once this is set up, you need to generate credentials so your Python script can talk to this project. See `Python_Connection.md`.
