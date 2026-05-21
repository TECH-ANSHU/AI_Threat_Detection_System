# Utilities Directory (`utils/`)

## Purpose
This directory houses modular helper scripts and helper functions supporting feature extraction, data preparation, visualization, and general cybersecurity configurations. Organizing these processes in `utils/` keeps the main application, detector, and training scripts lean, dry, and highly readable.

## Files Inside
- **`preprocessing.py`**: Builds the Scikit-learn ColumnTransformer pipeline which handles standardizing numeric columns (via `StandardScaler`) and encoding network protocol names (via `OneHotEncoder`). It also cleans null values.
- **`feature_engineering.py`**: Defines a stateful `FlowTracker` class that tracks packets flowing between specific IP pairs to calculate live rolling network flow features (like `flow_duration`, `packet_count`, and `byte_count`). It also provides a method to transform packets into inference-ready DataFrames.
- **`visualization.py`**: Integrates Plotly to generate high-fidelity, interactive HTML/JS plots (e.g. multi-axis timeseries graphs, pie charts, model metrics charts) designed specifically for a dark Security Operations Center (SOC) dashboard.
- **`helper.py`**: Implements port-to-service resolution mapping, IP address generators for simulation, local address lookup, and UI color mapping.

## System Interaction
1. **Model Pipeline**: `preprocessing.py` and `feature_engineering.py` are loaded during both training (`train_model.py`) and live detection (`detect.py`) to guarantee feature parity.
2. **Dashboard UI**: The Streamlit interface (`app.py`) loads `helper.py` for rendering details (e.g. converting port numbers to human-readable names like HTTPS, SMTP) and `visualization.py` to display graphs on the main monitor.
3. **Model Evaluation**: The training script `train_model.py` uses `visualization.py` to draw the Confusion Matrix and Feature Importance charts for the model health center.

## Future Upgrades
- Add support for deeper feature extraction (e.g., entropy of payloads, TCP flag ratios, sliding window entropy).
- Optimize `FlowTracker` with C-based extensions (or Cython) to scale under high gigabit-per-second packet rates.
- Incorporate GeoIP mapping helper in `helper.py` to map source/destination IPs to physical locations on a map visualization.
