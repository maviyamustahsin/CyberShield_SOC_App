import os
import time
import json
import logging
import asyncio
import pandas as pd
from fastapi import FastAPI, BackgroundTasks
from sse_starlette.sse import EventSourceResponse
from src.detection_engine import IntrusionDetectionEngine

app = FastAPI(title="SOC AI Intrusion Engine API")
logging.basicConfig(level=logging.INFO)

# Load engine upon startup
MODEL_DIR = r"c:\Users\Maaz\Desktop\cy\ai_ids_soc\models"
# We will use the test portion of the data to simulate traffic
TEST_DATA_PATH = r"c:\Users\Maaz\Desktop\cy\ai_ids_soc\data\cleaned_dataset.parquet"

engine = IntrusionDetectionEngine(MODEL_DIR)

# Global state
simulation_running = False
logs_queue = asyncio.Queue(maxsize=100)

async def traffic_simulator():
    global simulation_running
    try:
        logging.info("Reading test dataset for simulation...")
        # Since it's huge, we just read a chunk
        df = pd.read_parquet(TEST_DATA_PATH)
        df_sample = df.sample(n=min(50000, len(df)), random_state=42)
        
        # To simulate a real-world scenario, we mix in normal and attack traffic.
        # Ensure we drop Label to act as pure inference
        labels = df_sample.pop('Label').values if 'Label' in df_sample.columns else None
        
        logging.info("Simulation Started.")
        for idx, row in df_sample.iterrows():
            if not simulation_running:
                break
                
            flow_features = row.to_dict()
            
            # Predict
            result = engine.predict_flow(flow_features)
            
            # Create a log payload
            log_entry = {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "source_port": flow_features.get(" Source Port", 0),
                "destination_port": flow_features.get(" Destination Port", 0),
                "prediction": result["prediction"],
                "confidence": result["confidence"],
                "is_attack": result["is_attack"]
            }
            
            # Non-blocking push to the queue
            if not logs_queue.full():
                await logs_queue.put(log_entry)
            
            # Simulate real-time delay (e.g. 5-30 events per second)
            await asyncio.sleep(0.1)

    except Exception as e:
        logging.error(f"Simulator Error: {e}")
    finally:
        simulation_running = False
        logging.info("Simulation Stopped.")

@app.get("/start")
async def start_simulation(background_tasks: BackgroundTasks):
    global simulation_running
    if simulation_running:
        return {"status": "already running"}
    simulation_running = True
    background_tasks.add_task(traffic_simulator)
    return {"status": "started"}

@app.get("/stop")
async def stop_simulation():
    global simulation_running
    simulation_running = False
    return {"status": "stopped"}

async def event_generator():
    while True:
        try:
            # Wait for a new log entry
            log_entry = await asyncio.wait_for(logs_queue.get(), timeout=1.0)
            yield dict(data=json.dumps(log_entry))
        except asyncio.TimeoutError:
            # Send keep-alive packet if nothing is happening
            yield dict(data=json.dumps({"keepalive": True}))

@app.get("/stream")
async def stream():
    return EventSourceResponse(event_generator())
