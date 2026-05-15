import subprocess
import sys
import os

def install_local():
    # Define paths relative to the location of this script
    base_dir = os.path.dirname(os.path.abspath(__file__))
    req_file = os.path.join(base_dir, "python_dependencies.txt")
    target_dir = os.path.join(base_dir, "vendor")
    
    if not os.path.exists(req_file):
        print(f"[ERROR] Dependency file '{req_file}' not found.")
        sys.exit(1)
        
    print(f"📦 Installing dependencies into local directory: {target_dir}")
    print(f"📄 Reading from: {req_file}\n")
    
    try:
        # Use the current Python executable to run pip safely
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", 
            "-r", req_file, 
            "--target", target_dir,
            "--upgrade",
            "--quiet" # Keeps the output clean
        ])
        print("\n✅ Local installation complete! Lume Admin is ready to run.")
        
    except subprocess.CalledProcessError as e:
        print(f"\n[ERROR] Pip failed to install dependencies: {e}")
        sys.exit(1)

if __name__ == "__main__":
    install_local()
