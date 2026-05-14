from listener import Listener
from logger import get_logger

logger = get_logger(__name__)

@logger.catch
def main():
    listener = Listener("en0")
    listener.setup()
    listener.start()
    
if __name__ == "__main__":
    main()