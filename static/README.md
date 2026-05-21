# Static Directory (`static/`)

## Purpose
This directory stores static asset files (like style sheets, brand logos, or static client-side media) used to style and structure the user interface (UI) of the Security Operations Center (SOC) dashboard. 

## Files Inside
- **`styles.css`**: The main style overrides stylesheet. It contains custom glassmorphism CSS declarations, color badges for threat severity, blinking status indicator animations (online, scanning, alert), custom Google Fonts integrations, and clean dark cyber scrollbars.

## System Interaction
1. **Dashboard UI Customization**: The primary Streamlit frontend script `app.py` reads `static/styles.css` and injects its content directly into the HTML header using `st.markdown("<style>...</style>", unsafe_allow_html=True)`. This overrides standard Streamlit themes to force a customized cyber-operations theme.

## Future Upgrades
- Include localized threat icon images (e.g. Shield, Bug, Hacker graphics) inside this folder.
- Add JavaScript helper snippets if migrating to custom multi-window web rendering.
- Bundle localized SVG logos for branding the SOC interface.
