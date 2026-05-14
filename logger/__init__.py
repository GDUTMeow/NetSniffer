import sys
from datetime import datetime
from typing import Any
from pathlib import Path
from loguru import logger

_initialized = False

def _setup_global_logger():
    global _initialized
    if _initialized:
        return
    
    log_dir = Path("logs")
    log_dir.mkdir(parents=True, exist_ok=True)

    start_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    log_format = "{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {extra[name]}:{line} - {message}"

    logger.remove()

    logger.add(sys.stdout, format=log_format, level="INFO")

    common_kwargs: dict[str, Any] = {
        "rotation": "10 MB",
        "retention": "30 days",
        "encoding": "utf-8",
        "enqueue": True,
    }

    logger.add(
        log_dir / f"debug_{start_time}.log",
        format=log_format,
        level="DEBUG",
        filter=lambda record: record["level"].no >= logger.level("DEBUG").no,
        **common_kwargs
    )

    logger.add(
        log_dir / f"info_{start_time}.log",
        format=log_format,
        level="INFO",
        filter=lambda record: record["level"].no >= logger.level("INFO").no,
        **common_kwargs
    )

    logger.add(
        log_dir / f"error_{start_time}.log",
        format=log_format,
        level="ERROR",
        filter=lambda record: record["level"].no >= logger.level("ERROR").no,
        **common_kwargs
    )

    _initialized = True

def get_logger(name: str):
    _setup_global_logger()
    return logger.bind(name=name)