import pandas as pd
import numpy as np
import os
import gc

class DataProcessor:
    def __init__(self, data_path: str):
        self.data_path = data_path
    
    def reduce_mem_usage(self, df):
        """Iterate through all columns to modify data types to reduce memory usage."""
        start_mem = df.memory_usage().sum() / 1024**2
        print(f"Memory usage of dataframe is {start_mem:.2f} MB")
        
        for col in df.select_dtypes(include=['int', 'float']).columns:
            if 'int' in str(df[col].dtype):
                df[col] = pd.to_numeric(df[col], downcast='integer')
            elif 'float' in str(df[col].dtype):
                df[col] = pd.to_numeric(df[col], downcast='float')
        
        end_mem = df.memory_usage().sum() / 1024**2
        print(f"Memory usage after optimization is: {end_mem:.2f} MB")
        print(f"Decreased by {100 * (start_mem - end_mem) / start_mem:.1f}%")
        return df

    def clean_column_names(self, df):
        """Removes leading/trailing spaces from column names."""
        df.columns = df.columns.str.strip()
        print("Columns stripped of extra whitespace.")
        return df

    def load_and_clean_data(self) -> pd.DataFrame:
        """Loads data, handles infinite values, and drops NAs."""
        print(f"Loading data from {self.data_path}...")
        df = pd.read_csv(self.data_path, low_memory=False)
        
        df = self.clean_column_names(df)

        print("Removing repeated header rows if they exist...")
        df = df[df[df.columns[0]] != df.columns[0]]

        print("Coercing features to numeric...")
        features = [c for c in df.columns if c != 'Label']
        for col in features:
            df[col] = pd.to_numeric(df[col], errors='coerce')

        print("Handling missing and infinite values...")
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.dropna(inplace=True)

        print(f"Dataset shape after cleaning: {df.shape}")
        df = self.reduce_mem_usage(df)
        return df

    def process_and_save(self, output_dir: str):
        """Loads, cleans, and saves the engineered dataset to save time later."""
        df = self.load_and_clean_data()
        
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            
        out_path = os.path.join(output_dir, "cleaned_dataset.parquet")
        print(f"Saving cleaned dataset to {out_path}...")
        df.to_parquet(out_path, index=False)
        print("Data processing complete!")
        return df

if __name__ == "__main__":
    DATA_FILE = r"C:\Users\Maaz\Downloads\combinenew.csv"
    OUTPUT_DIR = r"c:\Users\Maaz\Desktop\cy\ai_ids_soc\data"
    
    processor = DataProcessor(DATA_FILE)
    df_clean = processor.process_and_save(OUTPUT_DIR)
