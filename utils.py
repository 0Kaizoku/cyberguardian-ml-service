import numpy as np
from typing import List


# Initialize DANGEROUS_PERMISSIONS as an empty list first
DANGEROUS_PERMISSIONS = []

# Dangerous permissions that might indicate malicious behavior
ALL_PERMISSIONS  = [
    "Your location : fine (GPS) location (D)",
    "Your location : coarse (network-based) location (D)",
    "Hardware controls : take pictures and videos (D)",
    "Hardware controls : record audio (D)",
    "Your personal information : read contact data (D)",
    "Your personal information : write contact data (D)",
    "Network communication : full Internet access (D)",
    "Services that cost you money : send SMS messages (D)",
    "Your messages : receive SMS (D)",
    "System tools : change Wi-Fi state (D)"
    "Your messages : read SMS or MMS (D)",
    "Storage : modify/delete USB storage contents modify/delete SD card contents (D)",
    "Hardware controls : control Bluetooth (D)",
    "System tools : change Wi-Fi state (D)",
    "Phone calls : read phone state and identity (D)",
    "Services that cost you money : directly call phone numbers (D)",
    "Phone calls : modify phone state (S)",
    "Network communication : view network state (S)",
    "Your messages : receive MMS (D)",
    "Your messages : receive WAP (D)",
    "Your messages : send SMS-received broadcast (S)",
    "Network communication : make/receive Internet calls (D)",
    "Your accounts : discover known accounts (S)",
    "Your accounts : manage the accounts list (D)",
    "Your accounts : act as an account authenticator (D)",
    "System tools : write sync settings (D)",
    "System tools : read sync settings (S)",
    "System tools : read sync statistics (S)",
    "System tools : set wallpaper (S)",
    "System tools : set wallpaper size hints (S)",
    "System tools : bluetooth administration (D)",
    "Hardware controls : connect to Bluetooth devices (D)",
    "Hardware controls : change your audio settings (D)",
    "Network communication : control Near Field Communication (D)",
    "System tools : prevent device from sleeping (D)",
    "Hardware controls : control vibrator (S)",
    "Hardware controls : control flashlight (S)",
    "Hardware controls : test hardware (S)",
    "Default : directly install applications (S)",
    "System tools : display system-level alerts (D)",
    "System tools : modify global system settings (D)",
    "Your personal information : read calendar events (D)",
    "Your personal information : add or modify calendar events and send email to guests (D)",
    "Your personal information : read user defined dictionary (D)",
    "Your personal information : write to user defined dictionary (S)",
    "Your personal information : set alarm in alarm clock (S)",
    # ...add more mapped permissions as needed from your backend mapping
    # ...add more mapped permissions as needed from your backend mapping
]

# Filter only (D) permissions after ALL_PERMISSIONS is defined
DANGEROUS_PERMISSIONS = [
    p for p in ALL_PERMISSIONS if p.endswith('(D)')  # Filter only (D) permissions
]
def feature_engineering(permissions: List[str]) -> np.ndarray:
    """
    Create a binary feature vector based on the DANGEROUS_PERMISSIONS list.

    Args:
        permissions: List of permission strings received from the frontend.

    Returns:
        np.ndarray: Binary feature vector of size len(DANGEROUS_PERMISSIONS).
    """
    # Initialize a binary vector of zeros with the same length as DANGEROUS_PERMISSIONS
    features = np.zeros(len(DANGEROUS_PERMISSIONS), dtype=int)

    # Set the corresponding index to 1 if the permission is present in the input
    for i, dangerous_permission in enumerate(DANGEROUS_PERMISSIONS):
        if dangerous_permission in permissions:
            features[i] = 1

    return features

def check_virustotal_api(sha256: str) -> str:
    """
    Placeholder for VirusTotal API integration
    In production, this would call the VirusTotal API to check app reputation
    
    Args:
        sha256: SHA256 hash of the APK file
    
    Returns:
        str: Status message about VirusTotal reputation
    """
    # TODO: Implement actual VirusTotal API call
    # Example API call would be:
    # response = requests.get(
    #     f"https://www.virustotal.com/api/v3/files/{sha256}",
    #     headers={"x-apikey": "YOUR_API_KEY"}
    # )
    
    # This is a placeholder response
    return f"VirusTotal API integration ready for {sha256[:8]}... (placeholder)"

def calculate_static_risk(permissions: List[str]) -> float:
    """
    Calculate static risk based on permissions alone
    This is a simple heuristic approach
    
    Args:
        permissions: List of permission strings
    
    Returns:
        float: Risk score between 0-1
    """
    if not permissions:
        return 0.0
        
    dangerous_count = sum(1 for p in permissions if p in DANGEROUS_PERMISSIONS)
    
    # Simple heuristic: risk is proportional to percentage of dangerous permissions
    # with a maximum threshold
    risk = min(1.0, dangerous_count / max(5, len(permissions) / 2))
    
    return risk

