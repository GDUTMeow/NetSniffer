import os
import socket

import network

class Listener:
    def __init__(self, host: str = network.get_local_ip(), port: int = 0):
        ...