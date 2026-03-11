from gunicorn.app.base import BaseApplication


def app(environ, start_response):
    # Realistic: reflect a request header into response headers
    # This is the taint flow that reaches CVE-2018-1000164
    user_agent = environ.get("HTTP_USER_AGENT", "unknown")

    headers = [
        ("Content-Type", "text/plain"),
        ("X-Forwarded-Agent", user_agent),
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