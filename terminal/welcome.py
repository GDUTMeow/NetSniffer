from textual.app import App, ComposeResult
from textual.screen import Screen
from textual.widgets import Header, Footer, Button, Label
from textual.containers import Vertical, Horizontal, Container

NETSNIFFER_ART = r""" _   _      _   ____        _  __  __           
| \ | | ___| |_/ ___| _ __ (_)/ _|/ _| ___ _ __ 
|  \| |/ _ \ __\___ \| '_ \| | |_| |_ / _ \ '__|
| |\  |  __/ |_ ___) | | | | |  _|  _|  __/ |   
|_| \_|\___|\__|____/|_| |_|_|_| |_|  \___|_|   """


class WelcomeScreen(Screen):
    def compose(self) -> ComposeResult:
        yield Header()
        yield Vertical(
            Label(NETSNIFFER_ART, id='welcome-title'),
            Label(
                "A computer network course project. Developed by [link='https://github.com/GamerNoTitle']@GamerNoTitle[/link].",
                id='welcome-subtitle',
            ),
            id='welcome-container',
        )
        yield Footer()
