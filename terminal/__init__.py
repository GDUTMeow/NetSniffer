from textual.app import App
from terminal.welcome import WelcomeScreen


class Application(App):
    CSS = """
    WelcomeScreen Vertical {
        align: center middle;
        width: 100%;
        height: 100%;
    }
    
    #welcome-title {
        text-align: center;
        width: 100%;
        height: auto;
        color: $primary;
        text-style: bold;
    }
    
    #welcome-subtitle {
        width: 100%;
        text-align: center;
        color: $secondary;
        margin-top: 1;
    }
    """

    SCREENS = {
        'welcome': WelcomeScreen,
    }

    def on_mount(self) -> None:
        self.push_screen('welcome')


application = Application()

__all__ = ['application']
