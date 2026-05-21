# Templates Directory (`templates/`)

## Purpose
This directory is reserved for holding template files (such as email bodies, PDF structures, HTML alert reports, or Slack webhook templates) used by the alert system when distributing security notifications to external channels.

## Future Files to Add
- **`email_alert_template.html`**: HTML/CSS template to format rich email alerts sent to security managers when a CRITICAL threat is detected.
- **`incident_report_template.html`**: HTML template for generating PDF summaries of resolved threat tickets.
- **`slack_payload_template.json`**: JSON template formatting webhook messages sent directly to Slack/Discord response channels.

## System Interaction
- The alert notification engine (e.g. future extensions of `alert_system.py`) will read templates from this folder, substitute incident values (source IP, severity, timestamp) into the template placeholders, and transmit the formatted alert.
