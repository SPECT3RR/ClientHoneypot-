import pyautogui
import time
import subprocess
import os
import signal

def run_test():
    print("Starting Orchestrator for 5-Cycle Weave Test...")
    # Launch orchestrator with unbuffered output
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    proc = subprocess.Popen(
        ["python", "src/v2_orchestrator.py", "https://example.com", "--headed"],
        env=env
    )
    
    time.sleep(10) # Let it load and bot start acting
    
    for cycle in range(1, 6):
        print(f"\n================ CYCLE {cycle} ================")
        print(">>> HUMAN TAKING OVER (Moving physical mouse...)")
        pyautogui.moveTo(100, 100, duration=0.2)
        pyautogui.moveTo(500, 500, duration=0.2)
        pyautogui.click()
        
        print(">>> HUMAN IDLE (Waiting 10 seconds for bot to resume...)")
        time.sleep(10)
        
    print("Test complete. Killing orchestrator...")
    proc.terminate()
    proc.wait()

if __name__ == "__main__":
    import sys
    run_test()
