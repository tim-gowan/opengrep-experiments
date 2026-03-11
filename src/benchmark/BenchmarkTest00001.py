import subprocess as sp

class BenchmarkTest00001:
    def __init__(self, data):
        self.data = data
        self.process()                    # Command Injection Sink.
        
    def process(self):
        sp.run(self.data, shell=True)     # Command Injection Sink.

    def execute(self, data):
        sp.Popen(data, shell=True)        # Command Injection Sink.

def process_func(data):
    sp.run(data, shell=True)              # Command Injection Sink.
