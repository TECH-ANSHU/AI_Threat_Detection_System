import pandas as pd
import numpy as np
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline

# Define features used in threat detection model
NUMERIC_FEATURES = ['source_port', 'destination_port', 'packet_length', 'flow_duration', 'packet_count', 'byte_count']
CATEGORICAL_FEATURES = ['protocol']
ALL_FEATURES = NUMERIC_FEATURES + CATEGORICAL_FEATURES

def get_preprocessing_pipeline():
    """Creates and returns the scikit-learn column preprocessor pipeline."""
    # Define numeric pipeline
    numeric_transformer = Pipeline(steps=[
        ('imputer', SimpleImputer(strategy='median')),
        ('scaler', StandardScaler())
    ])
    
    # Define categorical pipeline
    categorical_transformer = Pipeline(steps=[
        ('imputer', SimpleImputer(strategy='constant', fill_value='UNKNOWN')),
        ('onehot', OneHotEncoder(handle_unknown='ignore', sparse_output=False))
    ])
    
    # Bundle preprocessing for numeric and categorical data
    preprocessor = ColumnTransformer(
        transformers=[
            ('num', numeric_transformer, NUMERIC_FEATURES),
            ('cat', categorical_transformer, CATEGORICAL_FEATURES)
        ],
        remainder='drop'  # Drop other columns (like IPs, timestamps, etc.)
    )
    
    return preprocessor

def clean_data(df: pd.DataFrame) -> pd.DataFrame:
    """Cleans the input DataFrame, resolving nulls and formats data types."""
    df_clean = df.copy()
    
    # Ensure numeric types
    for col in NUMERIC_FEATURES:
        if col in df_clean.columns:
            df_clean[col] = pd.to_numeric(df_clean[col], errors='coerce')
            
    # Ensure categorical types
    for col in CATEGORICAL_FEATURES:
        if col in df_clean.columns:
            df_clean[col] = df_clean[col].astype(str).str.upper()
            
    return df_clean
