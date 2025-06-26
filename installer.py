import subprocess
import sys

libraries = {
    'pycryptodome': {'install': 'pycryptodome', 'import': 'Crypto'},
}

def install(libs):
    for name, lib in libs.items():
        try:
            __import__(lib['import'])
            print(f"{name} already installed.")
        except ImportError:
            print(f"{name} not found. Installing...")
            try:
                subprocess.check_call([sys.executable, '-m', 'pip', 'install', lib['install']])
                print(f"{name} installed successfully.")
            except subprocess.CalledProcessError:
                print(f"Failed to install {name}. Fix your shit and retry.")
            except FileNotFoundError:
                print("pip not found. Attempting to install pip...")
                try:
                    subprocess.check_call([sys.executable, '-m', 'ensurepip'])
                    print("pip installed successfully.")
                    subprocess.check_call([sys.executable, '-m', 'pip', 'install', lib['install']])
                    print(f"{name} installed successfully after pip setup.")
                except subprocess.CalledProcessError:
                    print("Failed to install pip. Fix your environment and retry.")

print("Press ENTER to start the installer:")
input()
install(libraries)
print("Done installing required libraries.")
print("Press ENTER to exit.")
input()
