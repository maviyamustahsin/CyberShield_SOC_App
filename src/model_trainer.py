import pandas as pd
import numpy as np
import os
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, accuracy_score

class ModelTrainer:
    def __init__(self, data_path: str, model_dir: str):
        self.data_path = data_path
        self.model_dir = model_dir
        
        if not os.path.exists(self.model_dir):
            os.makedirs(self.model_dir)

    def load_data(self):
        print("Loading processed dataset...")
        df = pd.read_parquet(self.data_path)
        return df

    def train_and_evaluate(self):
        df = self.load_data()
        
        # InCICIDS, the target variable is usually 'Label'
        if 'Label' not in df.columns:
            print("Error: 'Label' column not found!")
            return

        print("Encoding labels...")
        le = LabelEncoder()
        df['Label_encoded'] = le.fit_transform(df['Label'])
        
        # Save Label Encoder
        joblib.dump(le, os.path.join(self.model_dir, 'label_encoder.pkl'))
        
        y = df['Label_encoded']
        X = df.drop(columns=['Label', 'Label_encoded'])

        print("Splitting dataset...")
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

        print("Scaling features...")
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        # Save Scaler
        joblib.dump(scaler, os.path.join(self.model_dir, 'scaler.pkl'))
        # Save feature names for the detection engine
        joblib.dump(X.columns.tolist(), os.path.join(self.model_dir, 'feature_names.pkl'))

        print("Training Random Forest Classifier (this may take a while)...")
        # Use a random forest with n_jobs=-1 for multi-core processing
        clf = RandomForestClassifier(n_estimators=50, max_depth=20, random_state=42, n_jobs=-1)
        clf.fit(X_train_scaled, y_train)

        print("Evaluating model...")
        y_pred = clf.predict(X_test_scaled)
        acc = accuracy_score(y_test, y_pred)
        print(f"Accuracy: {acc:.4f}")
        print("\nClassification Report:\n", classification_report(y_test, y_pred, target_names=le.classes_))

        print("Saving model mechanism...")
        joblib.dump(clf, os.path.join(self.model_dir, 'rf_model.pkl'))
        print(f"Model and artifacts successfully saved to {self.model_dir}")

if __name__ == "__main__":
    DATA_PATH = r"c:\Users\Maaz\Desktop\cy\ai_ids_soc\data\cleaned_dataset.parquet"
    MODEL_DIR = r"c:\Users\Maaz\Desktop\cy\ai_ids_soc\models"
    
    trainer = ModelTrainer(DATA_PATH, MODEL_DIR)
    trainer.train_and_evaluate()
