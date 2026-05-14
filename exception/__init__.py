class NetSnifferException(Exception):
    """Base class for all exceptions in NetSniffer."""
    def __init__(self, message: str = "An error occurred in NetSniffer."):
        super().__init__(message)
        
class OptionError(NetSnifferException):
    """Raised when the options provided are invalid."""
    def __init__(self, message: str = "Invalid options provided."):
        super().__init__(message)
        
class NotFoundError(NetSnifferException):
    """Raised when a required resource is not found."""
    def __init__(self, message: str = "Required resource not found."):
        super().__init__(message)