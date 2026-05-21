# Models Directory (`models/`)

## Purpose
This directory stores the serialized, pre-trained Machine Learning (ML) classification pipelines. These pipelines contain the fitted transformers (preprocessors) and the Random Forest classification models, allowing the system to perform high-speed inference without re-training.

## Files Inside
- **`threat_model.pkl`**: The active trained model pipeline. It is serialized using `joblib` and contains:
  1. The ColumnTransformer preprocessor (scaling numerical columns, one-hot encoding protocols).
  2. The fitted Random Forest Classifier.

## System Interaction
1. **Serialization**: The training script `train_model.py` builds the pipeline, fits it using data from `dataset/sample_dataset.csv`, evaluates it, and serializes the complete pipeline directly to `models/threat_model.pkl`.
2. **Inference**: The detection engine `detect.py` loads `threat_model.pkl` on startup. When a packet is intercepted or simulated, the engine feeds it into this model pipeline to calculate prediction probabilities and threat categories.

## Future Upgrades
- Implement model versioning (e.g. `threat_model_v1.pkl`, `threat_model_v2.pkl`) to support hot-swaps or rolling updates.
- Store model metrics (ROC-AUC, confusion matrices) as metadata files next to the model artifact.
- Integrate deep learning model checkpoints (e.g., PyTorch LSTMs or Autoencoders for anomaly detection) in this directory.
