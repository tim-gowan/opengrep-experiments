import os

class BenchmarkTest00003:
    def __init__(self, data):
        self.data = data
        self.execute(data)
    
    def execute(self, data):
        os.system(data)

