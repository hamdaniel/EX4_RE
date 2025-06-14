import os
import subprocess

# === Configuration ===
scripts_folder = r"tests"  # <- Change this to your folder path

# === Execution ===
for filename in os.listdir(scripts_folder):
    if filename.endswith(".py"):
        full_path = os.path.join(scripts_folder, filename)
        print(f"Running {full_path}")
        subprocess.run(["python", full_path], check=True)
