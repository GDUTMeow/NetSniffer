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


class SetupRequiredError(NetSnifferException):
    """Raised when an operation is attempted before setup is complete."""

    def __init__(
        self, message: str = "Setup is required before this operation can be performed."
    ):
        super().__init__(message)


class PacketLengthNotSatisfiedError(NetSnifferException):
    """Raised when a packet is too short to be parsed."""

    def __init__(self, message: str = "Packet length is not sufficient for parsing."):
        super().__init__(message)


class MalformedTCPOptionError(NetSnifferException):
    """Raised when a TCP option is malformed."""

    def __init__(self, message: str = "Malformed TCP option encountered."):
        super().__init__(message)


class ParamsNotSatisfiedError(NetSnifferException):
    """Raised when the parameters provided do not satisfy the requirements."""

    def __init__(
        self, message: str = "Provided parameters do not satisfy the requirements."
    ):
        super().__init__(message)


class CursorOutOfBoundsError(NetSnifferException):
    """Raised when a cursor goes out of bounds while parsing."""

    def __init__(self, message: str = "Cursor went out of bounds during parsing."):
        super().__init__(message)
