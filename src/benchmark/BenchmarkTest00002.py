import sys
from benchmark.BenchmarkTest00001 import BenchmarkTest00001
from benchmark.BenchmarkTest00001 import process_func

data1 = sys.argv[1]                                                     # Source
class BenchmarkTest00002:
    def __init__(self, data) -> None:
        self.processor = BenchmarkTest00001(data)                       # Class Boundary
        # Opengrep: Propagation is not captured past constructor boundaries.
        self.data2 = sys.argv[2]                                         # Source
    def handle(self, data) -> None:
        self.processor.execute(data)
        
    class BenchmarkTest00002_Subclass(BenchmarkTest00001):              # Subclass that implements an external class.
        def __init__(self, data) -> None:
            super().__init__(data)
        def process(self) -> None:
            self.execute(self.data)                                     # Method override from external class.

if __name__ == "__main__":
    manager = BenchmarkTest00002(data1)
    manager.handle(manager.data2) 
    data3 = sys.argv[3]                                                 # Source
    manager.processor.execute(data3) 
    data4 = sys.argv[4]                                                 # Source
    process_func(data4)
    data5 = sys.argv[5]                                                 # Source
    extended = manager.BenchmarkTest00002_Subclass(data5 + "")

