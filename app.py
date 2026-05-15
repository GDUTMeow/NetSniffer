from listener import Listener
from logger import get_logger
from parser import Parser

logger = get_logger(__name__)
parser = Parser()

@logger.catch
def main():
    listener = Listener('en0')
    # listener = Listener('enp0s5')
    # listener = Listener('{016BF61E-E718-49D8-947F-4D00BF7B3A25}')
    listener.setup()
    listener.start(handler=parser.parse_ethernet)


if __name__ == '__main__':
    main()
