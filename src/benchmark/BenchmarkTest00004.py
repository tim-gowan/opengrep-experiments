import argparse
from benchmark.BenchmarkTest00003 import BenchmarkTest00003

parser = argparse.ArgumentParser()
parser.add_argument("data", type=str)
args = parser.parse_args()

class BenchmarkTest00004:
    def __init__(self, data):
        self.executor = BenchmarkTest00003(data)
    
    def run(self, data):
        self.executor.execute(data)

if __name__ == "__main__":
    data = getattr(args, 'data')
    parser = BenchmarkTest00004(data)

    data = vars(args)['data']
    parser.run(data)

    attr_name = 'data'
    data = getattr(args, attr_name)
    parser.run(data)

