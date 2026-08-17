import os
import subprocess
from datetime import datetime

from acquisition.preflight import check_storage_for_acquisition

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DUMP_DIR = os.path.join(BASE_DIR, "dumps")
TOOLS_DIR = os.path.join(BASE_DIR, "tools")
os.makedirs(DUMP_DIR, exist_ok=True)


def take_snapshot(os_type, custom_path=None):
    dump_dir = DUMP_DIR
    if custom_path:
        dump_dir = os.path.dirname(os.path.abspath(custom_path)) or DUMP_DIR

    storage_check = check_storage_for_acquisition(dump_dir, os_type)
    if storage_check.message.startswith("[INFO]"):
        print(storage_check.message)
    elif storage_check.message.startswith("[WARNING]"):
        print(storage_check.message)
    if not storage_check.ok:
        print(storage_check.message)
        return None

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    dump_file = os.path.join(DUMP_DIR, f"memory_dump_{timestamp}.raw")
    if custom_path:
        dump_file = custom_path

    try:
        if os_type == "Windows":
            winpmem_path = os.path.join(TOOLS_DIR, "winpmem.exe")
            command = [
                winpmem_path,
                "acquire",
                dump_file
            ]
            subprocess.run(command, check=True)
            return dump_file

        elif os_type == "Linux":
            lime_ko_path = os.path.join(TOOLS_DIR, "lime.ko")

            if not os.path.exists(lime_ko_path):
                print("[ERROR] lime.ko not found in tools folder")
                return None

            subprocess.run(["rmmod", "lime"], check=False, stderr=subprocess.DEVNULL)

            command = [
                "insmod",
                lime_ko_path,
                f"path={dump_file}",
                "format=lime"
            ]
            subprocess.run(command, check=True)

            subprocess.run(["rmmod", "lime"], check=False, stderr=subprocess.DEVNULL)

            return dump_file

        else:
            return None

    except subprocess.CalledProcessError as e:
        print(f"[ERROR] RAM acquisition failed: {e}")
        return None