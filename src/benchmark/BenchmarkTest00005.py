import sqlite3

class BenchmarkTest00005:
    def __init__(self, data):                        # Source
        self.data = data                             # Taint Propagation

    def execute(self):                                
        connection = sqlite3.connect("example.db")
        cursor = connection.cursor()
        cursor.executescript(self.data)               # Class attribute access to taint
        connection.commit()
        connection.close()

