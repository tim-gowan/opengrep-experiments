from flask import Flask, request
from benchmark.BenchmarkTest00005 import BenchmarkTest00005

app = Flask(__name__)


class BenchmarkTest00006:
    def __init__(self, application):
        self.app = application

    def start(self):
        @self.app.route("/query", methods=["GET"])
        def query():
            param = request.args.get("q", "")       # Source
            database = BenchmarkTest00005(param)    # Class Boundary + Taint Propagation
            database.execute()                      # Method override from external class. SQLi Sink triggered
            return "query executed"

        self.app.run()


if __name__ == "__main__":
    service = BenchmarkTest00006(app)
    service.start()

