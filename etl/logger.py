
import logging
from pathlib import Path

# Create logs folder
LOG_FOLDER = Path("logs")
LOG_FOLDER.mkdir(parents=True, exist_ok=True)

# Log file location
LOG_FILE = LOG_FOLDER / "platform.log"

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler()
    ],
    force=True
)

# Create a logger
logger = logging.getLogger("CyberThreatPlatform")
