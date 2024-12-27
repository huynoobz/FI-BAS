import os
import subprocess
import urllib.request
import platform
import ctypes

def win():
    def download_nmap_installer(url, save_path):
        print("Downloading Nmap installer...")
        urllib.request.urlretrieve(url, save_path)
        print("Download complete.")

    def install_nmap(installer_path):
        print("Installing Nmap...")
        subprocess.run([installer_path, '/S'], check=True)  # /S for silent installation
        print("Nmap installation complete.")

    def add_to_path(nmap_path):
        print("Adding Nmap to system PATH...")
        current_path = os.environ['PATH']
        if nmap_path not in current_path:
            os.environ['PATH'] = current_path + os.pathsep + nmap_path
            print("Nmap path added: {}".format(nmap_path))
        else:
            print("Nmap is already in the PATH.")

    ###
    # URL to the Nmap installer (64-bit version from the official website)
    nmap_url = "https://nmap.org/dist/nmap-7.95-setup.exe"  # Update URL as needed
    installer_path = "nmap-installer.exe"
    
    # Download the installer
    download_nmap_installer(nmap_url, installer_path)
    
    # Run the installer
    install_nmap(installer_path)
    
    # Optional: Add to PATH manually (if not already added by the installer)
    nmap_install_path = r"C:\Program Files (x86)\Nmap"
    add_to_path(nmap_install_path)
    
    # Cleanup: Remove the installer
    os.remove(installer_path)
    print("Installer removed.")

def ask_privileges(os_type):
    if os_type == "Windows":
        # Request admin privileges on Windows
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("Need administrator privileges!\nHint: Run as administrator ...")
            exit(1)
    
    elif os_type == "Linux" or os_type == "Darwin":  # Darwin is macOS
        # Use sudo for Linux/macOS
        if os.geteuid() != 0:
            print("Need administrator privileges!\nHint: sudo ...")

def install_r_python_package():
    try:
        print(f"Installing require Python package...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
    except subprocess.CalledProcessError:
        print(f"Failed to install require Python package...")
        sys.exit(1)

if __name__ == "__main__":
    os_name = os.name
    if os_name == 'nt':
        print("Operating System: Windows")
        ask_privileges("Windows")
        win()
    elif os_name == 'posix':
        print("Operating System: Unix/Linux/MacOS")
        ask_privileges("Linux")
    else:
        print("Operating System: {}".format(os_name))

    install_r_python_package()

