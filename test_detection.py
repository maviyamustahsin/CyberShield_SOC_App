import pandas as pd
import sys, os
sys.path.append(os.path.abspath('.'))
from src.detection_engine import IntrusionDetectionEngine

engine = IntrusionDetectionEngine('models')
df = pd.read_parquet('data/cloud_demo_dataset.parquet')

# Test 10 attack rows and 5 benign rows
attacks = df[df['Label'] != 'BENIGN'].head(10)
benign = df[df['Label'] == 'BENIGN'].head(5)

print('=== TESTING ATTACK ROWS ===')
for i, (_, row) in enumerate(attacks.iterrows()):
    feat = row.to_dict()
    label = feat.pop('Label')
    result = engine.predict_flow(feat)
    print(f"Row {i}: Label={label} -> is_attack={result['is_attack']}, pred={result['prediction']}, conf={result['confidence']:.2f}")

print()
print('=== TESTING BENIGN ROWS ===')
for i, (_, row) in enumerate(benign.iterrows()):
    feat = row.to_dict()
    label = feat.pop('Label')
    result = engine.predict_flow(feat)
    print(f"Row {i}: Label={label} -> is_attack={result['is_attack']}, pred={result['prediction']}, conf={result['confidence']:.2f}")
