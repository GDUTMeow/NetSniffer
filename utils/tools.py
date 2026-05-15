import time
from httpx import Client, HTTPError

from exception import ParamsNotSatisfiedError
from logger import get_logger

logger = get_logger(__name__)

class fileHandler:
    # A file handler over http, which will dump the file content from the request/response and save as a file.
    def __init__(self, save_dir: str):
        self.save_dir = save_dir
        self.client = Client()
        logger.info(f"File handler initialized with save directory: {self.save_dir}")
        
    def handle(self, raw: bytes | None = None, link: str | None = None, extension: str = "bin"):
        if not raw and not link:
            raise ParamsNotSatisfiedError("Either raw data or a link must be provided to handle the file.")
        if raw:
            filename = f"{self.save_dir}/file_{int(time.time())}.{extension}"
            with open(filename, "wb") as f:
                f.write(raw)
            logger.info(f"File saved to {filename}")
        elif link:
            filename = f"{self.save_dir}/file_{int(time.time())}.{extension}"
            try:
                response = self.client.get(link)
                response.raise_for_status()
                with open(filename, "wb") as f:
                    f.write(response.content)
                logger.info(f"File downloaded from {link} and saved to {filename}")
            except HTTPError as e:
                logger.error(f"Failed to download file from {link}: {e}")