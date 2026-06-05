"""
IoT Shield Launcher — Auto-starts services and launches the GUI.

This script is the entry point for the packaged Windows EXE. It:
1. Checks for required dependencies (Nmap)
2. Starts optional services (Ollama) in the background
3. Launches the main GUI application
4. Handles graceful error recovery

Usage:
    python launcher.py      # Normal launch
    python launcher.py --no-services  # Skip service startup
"""

import os
import sys
import subprocess
import time
import socket
import shutil
from pathlib import Path
from typing import Optional
import logging

# Add parent directory to path so we can import iden_coop modules
_HERE = Path(__file__).parent
sys.path.insert(0, str(_HERE.parent))

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION (inlined to avoid import issues in PyInstaller)
# ═══════════════════════════════════════════════════════════════════════════════

APP_NAME = "IoT Shield"
COMPANY_NAME = "Iden Ltd"

SERVICES = {
    "ollama": {
        "executable": "ollama.exe",
        "args": ["serve"],
        "host": "http://localhost:11434",
        "required": False,
        "wait_seconds": 5,
    },
    "nmap": {
        "check_only": True,
        "executable": "nmap.exe",
        "required": True,
    },
}

# ═══════════════════════════════════════════════════════════════════════════════
# LOGGING SETUP
# ═══════════════════════════════════════════════════════════════════════════════

logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s',
)
logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════════
# SERVICE MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

class ServiceManager:
    """Manages startup and health checks for background services."""

    def __init__(self):
        self.processes: dict[str, subprocess.Popen] = {}
        self.failed_services: set[str] = set()

    def check_executable_exists(self, name: str) -> bool:
        """Check if an executable exists in PATH."""
        return shutil.which(name) is not None

    def is_port_open(self, host: str, port: int, timeout: float = 2.0) -> bool:
        """Check if a service is listening on a port."""
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.close()
            return True
        except (socket.timeout, socket.error):
            return False

    def start_service(self, name: str, config: dict) -> bool:
        """
        Start a background service.

        Args:
            name: Service name (e.g., 'ollama')
            config: Service configuration dict with 'executable', 'args', etc.

        Returns:
            True if started successfully, False otherwise.
        """
        logger.info(f"Starting {name.capitalize()}...")

        executable = config.get("executable")
        if not executable:
            logger.warning(f"No executable configured for {name}")
            return False

        # Check if executable exists
        exe_path = shutil.which(executable)
        if not exe_path:
            logger.error(
                f"{executable} not found in PATH. "
                f"Please install {name.capitalize()} from {config.get('url', 'official website')}"
            )
            self.failed_services.add(name)
            return False

        # Start service
        try:
            args = config.get("args", [])
            proc = subprocess.Popen(
                [exe_path] + args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NEW_CONSOLE if sys.platform == "win32" else 0,
            )
            self.processes[name] = proc
            logger.info(f"✓ {name.capitalize()} started (PID {proc.pid})")

            # Wait for service to be ready
            if "wait_seconds" in config:
                wait_time = config["wait_seconds"]
                logger.info(f"  Waiting {wait_time}s for {name} to initialize...")
                time.sleep(wait_time)

                # Check if service is responsive (for services with ports)
                if "host" in config and ":" in config["host"]:
                    host_port = config["host"].split("://")[1]  # Extract localhost:port
                    host, port = host_port.split(":")
                    if self.is_port_open(host, int(port)):
                        logger.info(f"✓ {name.capitalize()} is responsive")
                    else:
                        logger.warning(f"⚠ {name.capitalize()} not responding yet (may still be initializing)")

            return True

        except Exception as e:
            logger.error(f"Failed to start {name}: {e}")
            self.failed_services.add(name)
            return False

    def check_required_tools(self) -> bool:
        """
        Check for required external tools.

        Returns:
            True if all required tools are available, False otherwise.
        """
        all_available = True

        for name, config in SERVICES.items():
            if config.get("check_only"):
                if self.check_executable_exists(config["executable"]):
                    logger.info(f"✓ {name.capitalize()} found")
                else:
                    if config.get("required"):
                        logger.error(
                            f"✗ {name.capitalize()} not found in PATH\n"
                            f"  Please install from: https://nmap.org/download.html"
                        )
                        all_available = False
                    else:
                        logger.warning(f"⚠ {name.capitalize()} not found (optional)")

        return all_available

    def start_optional_services(self) -> None:
        """Start optional services (Ollama, etc.) in background."""
        for name, config in SERVICES.items():
            if config.get("check_only"):
                continue  # Skip check-only services

            if not config.get("required", False):
                # Optional service — attempt to start but don't fail
                self.start_service(name, config)

    def cleanup(self) -> None:
        """Terminate all managed processes."""
        logger.info("Cleaning up services...")
        for name, proc in self.processes.items():
            try:
                proc.terminate()
                proc.wait(timeout=5)
                logger.info(f"✓ {name.capitalize()} stopped")
            except subprocess.TimeoutExpired:
                proc.kill()
                logger.warning(f"⚠ {name.capitalize()} force-killed")
            except Exception as e:
                logger.warning(f"Error stopping {name}: {e}")

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN LAUNCHER
# ═══════════════════════════════════════════════════════════════════════════════

def main() -> int:
    """
    Main launcher routine.

    Returns:
        Exit code (0 = success, non-zero = error)
    """
    logger.info(f"{'=' * 70}")
    logger.info(f"{APP_NAME} v1.0.0 — {COMPANY_NAME}")
    logger.info(f"{'=' * 70}")

    # Parse command-line arguments
    skip_services = "--no-services" in sys.argv

    # Initialize service manager
    manager = ServiceManager()

    # Check for required tools
    if not manager.check_required_tools():
        logger.error("\n⚠ Installation incomplete. Please install missing components.")
        input("Press Enter to exit...")
        return 1

    # Start optional services
    if not skip_services:
        logger.info("\nStarting background services...")
        manager.start_optional_services()

        if manager.failed_services:
            logger.warning(
                f"\n⚠ {len(manager.failed_services)} service(s) failed to start: "
                f"{', '.join(manager.failed_services)}\n"
                f"  The application will run with limited features."
            )

    # Launch GUI
    logger.info("\nLaunching GUI...")
    try:
        # Import and run the main GUI application
        from gui.iot_scanner_gui import main as gui_main

        gui_main()

    except ImportError as e:
        logger.error(f"Failed to import GUI module: {e}")
        logger.error("Please ensure the application is installed correctly.")
        return 1
    except Exception as e:
        logger.error(f"GUI application error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    finally:
        # Always clean up services on exit
        manager.cleanup()

    logger.info(f"\n{APP_NAME} exited successfully.")
    return 0


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
