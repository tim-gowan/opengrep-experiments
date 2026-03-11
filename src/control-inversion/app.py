from gunicorn.app.base import BaseApplication


def app(environ, start_response):
    injected_value = "safe-value\r\nX-Injected: yes"

    headers = [
        ("Content-Type", "text/plain"),
        ("X-Test", injected_value),
    ]

    start_response("200 OK", headers)
    return [b"gunicorn test\n"]


class StandaloneGunicornApplication(BaseApplication):
    def __init__(self, application, options=None):
        self.options = options or {}
        self.application = application
        super().__init__()

    def load_config(self):
        for key, value in self.options.items():
            if key in self.cfg.settings and value is not None:
                self.cfg.set(key.lower(), value)

    def load(self):
        return self.application


if __name__ == "__main__":
    options = {
        "bind": "127.0.0.1:8000",
        "workers": 1,
    }

    StandaloneGunicornApplication(app, options).run()