# Manual True Positive Trace - Direct Code Analysis

## Methodology
Tracing taint flows from sources (sys.argv, argparse, request.args) to sinks (subprocess.run, subprocess.Popen, os.system, sqlite3.executescript) by following the actual code execution paths.

---

## BenchmarkTest00001.py Analysis

### Sinks Identified:
1. **Line 9:** `sp.run(self.data, shell=True)` in `BenchmarkTest00001.process()`
2. **Line 12:** `sp.Popen(data, shell=True)` in `BenchmarkTest00001.execute(data)`
3. **Line 15:** `sp.run(data, shell=True)` in standalone `process(data)` function

---

## BenchmarkTest00002.py Analysis

### Sources Identified:
- **Line 5:** `data1 = sys.argv[1]` 
- **Line 9:** `self.data2 = sys.argv[2]` (in `__init__`)
- **Line 22:** `data3 = sys.argv[3]`
- **Line 24:** `data4 = sys.argv[4]`
- **Line 26:** `data5 = sys.argv[5]`

### Execution Flow (lines 19-27):
```python
if __name__ == "__main__":
    manager = BenchmarkTest00002(data1)      # Line 20
    manager.handle(manager.data2)            # Line 21
    data3 = sys.argv[3]                      # Line 22
    manager.processor.execute(data3+ "")      # Line 23
    data4 = sys.argv[4]                      # Line 24
    process(data4)                            # Line 25
    data5 = sys.argv[5]                       # Line 26
    extended = manager.BenchmarkTest00002_Subclass(data5)        # Line 27
```

---

## TRUE POSITIVE #1: sys.argv[1] → sp.run in BenchmarkTest00001.__init__

### Source:
- **File:** `src/benchmark/BenchmarkTest00002.py`
- **Line:** 5
- **Code:** `data1 = sys.argv[1]`
- **Type:** External input (command-line argument)

### Sink:
- **File:** `src/benchmark/BenchmarkTest00001.py`
- **Line:** 9
- **Code:** `sp.run(self.data, shell=True)`
- **Method:** `BenchmarkTest00001.process()`

### Taint Flow Path:
1. **Line 5 (BenchmarkTest00002.py):** `data1 = sys.argv[1]` ← **SOURCE**
2. **Line 20 (BenchmarkTest00002.py):** `manager = BenchmarkTest00002(data1)`
   - Calls `BenchmarkTest00002.__init__(data1)`
3. **Line 8 (BenchmarkTest00002.py):** `self.processor = BenchmarkTest00001(data)`
   - Calls `BenchmarkTest00001.__init__(data)` where `data = data1`
4. **Line 4 (BenchmarkTest00001.py):** `def __init__(self, data):`
   - Parameter `data` receives `data1` (tainted)
5. **Line 5 (BenchmarkTest00001.py):** `self.data = data`
   - Stores tainted value in `self.data`
6. **Line 6 (BenchmarkTest00001.py):** `self.process()`
   - Calls `process()` method
7. **Line 9 (BenchmarkTest00001.py):** `sp.run(self.data, shell=True)` ← **SINK**

### Evidence:
- Direct constructor chain: `BenchmarkTest00002(data1)` → `BenchmarkTest00001(data1)`
- Taint propagates through: `data1` → `data` parameter → `self.data` → `sp.run(self.data)`

### Confidence: **HIGH** ✅
- Direct parameter passing
- No transformations
- Verified call path in class index

---

## TRUE POSITIVE #2: sys.argv[2] → sp.Popen in BenchmarkTest00001.execute

### Source:
- **File:** `src/benchmark/BenchmarkTest00002.py`
- **Line:** 9
- **Code:** `self.data2 = sys.argv[2]`
- **Type:** External input (command-line argument)

### Sink:
- **File:** `src/benchmark/BenchmarkTest00001.py`
- **Line:** 12
- **Code:** `sp.Popen(data, shell=True)`
- **Method:** `BenchmarkTest00001.execute(data)`

### Taint Flow Path:
1. **Line 9 (BenchmarkTest00002.py):** `self.data2 = sys.argv[2]` ← **SOURCE**
   - In `BenchmarkTest00002.__init__()`
2. **Line 21 (BenchmarkTest00002.py):** `manager.handle(manager.data2)`
   - Calls `handle()` method with `manager.data2` (tainted)
3. **Line 10 (BenchmarkTest00002.py):** `def handle(self, data) -> None:`
   - Parameter `data` receives `manager.data2` (tainted)
4. **Line 11 (BenchmarkTest00002.py):** `self.processor.execute(data)`
   - Calls `BenchmarkTest00001.execute(data)` where `data = manager.data2` (tainted)
5. **Line 11 (BenchmarkTest00001.py):** `def execute(self, data):`
   - Parameter `data` receives tainted value
6. **Line 12 (BenchmarkTest00001.py):** `sp.Popen(data, shell=True)` ← **SINK**

### Evidence:
- Method call chain: `manager.handle(manager.data2)` → `self.processor.execute(data)`
- Taint propagates through: `sys.argv[2]` → `self.data2` → `data` parameter → `sp.Popen(data)`

### Confidence: **HIGH** ✅
- Direct parameter passing through method calls
- Verified in class index: `BenchmarkTest00002.handle` → `BenchmarkTest00001.execute`

---

## TRUE POSITIVE #3: sys.argv[3] → sp.Popen in BenchmarkTest00001.execute

### Source:
- **File:** `src/benchmark/BenchmarkTest00002.py`
- **Line:** 22
- **Code:** `data3 = sys.argv[3]`
- **Type:** External input (command-line argument)

### Sink:
- **File:** `src/benchmark/BenchmarkTest00001.py`
- **Line:** 12
- **Code:** `sp.Popen(data, shell=True)`
- **Method:** `BenchmarkTest00001.execute(data)`

### Taint Flow Path:
1. **Line 22 (BenchmarkTest00002.py):** `data3 = sys.argv[3]` ← **SOURCE**
2. **Line 23 (BenchmarkTest00002.py):** `manager.processor.execute(data3+ "")`
   - Calls `BenchmarkTest00001.execute(data3+ "")`
   - Note: `data3+ ""` is still tainted (string concatenation doesn't sanitize)
3. **Line 11 (BenchmarkTest00001.py):** `def execute(self, data):`
   - Parameter `data` receives `data3+ ""` (tainted)
4. **Line 12 (BenchmarkTest00001.py):** `sp.Popen(data, shell=True)` ← **SINK**

### Evidence:
- Direct method call: `manager.processor.execute(data3)`
- Nested attribute access: `manager.processor` → `BenchmarkTest00001` instance
- Taint propagates through: `sys.argv[3]` → `data3` → `data` parameter → `sp.Popen(data)`

### Confidence: **HIGH** ✅
- Direct parameter passing
- Nested method call verified in class index

---

## TRUE POSITIVE #4: sys.argv[4] → sp.run in process() function

### Source:
- **File:** `src/benchmark/BenchmarkTest00002.py`
- **Line:** 24
- **Code:** `data4 = sys.argv[4]`
- **Type:** External input (command-line argument)

### Sink:
- **File:** `src/benchmark/BenchmarkTest00001.py`
- **Line:** 15
- **Code:** `sp.run(data, shell=True)`
- **Function:** `process(data)` (standalone function, not a method)

### Taint Flow Path:
1. **Line 24 (BenchmarkTest00002.py):** `data4 = sys.argv[4]` ← **SOURCE**
2. **Line 3 (BenchmarkTest00002.py):** `from benchmark.BenchmarkTest00001 import process`
   - Imports `process` function
3. **Line 25 (BenchmarkTest00002.py):** `process(data4)`
   - Calls `process()` function with `data4` (tainted)
4. **Line 14 (BenchmarkTest00001.py):** `def process(data):`
   - Parameter `data` receives `data4` (tainted)
5. **Line 15 (BenchmarkTest00001.py):** `sp.run(data, shell=True)` ← **SINK**

### Evidence:
- Direct function call: `process(data4)`
- Imported function from `BenchmarkTest00001`
- Taint propagates through: `sys.argv[4]` → `data4` → `data` parameter → `sp.run(data)`

### Confidence: **HIGH** ✅
- Direct function call
- No class boundaries
- Simple parameter passing

---

## TRUE POSITIVE #5: sys.argv[5] → sp.Popen in BenchmarkTest00001.execute (via BenchmarkTest00002_Subclass.process)

### Source:
- **File:** `src/benchmark/BenchmarkTest00002.py`
- **Line:** 26
- **Code:** `data5 = sys.argv[5]`
- **Type:** External input (command-line argument)

### Sink:
- **File:** `src/benchmark/BenchmarkTest00001.py`
- **Line:** 12
- **Code:** `sp.Popen(data, shell=True)`
- **Method:** `BenchmarkTest00001.execute(data)`

### Taint Flow Path:
1. **Line 26 (BenchmarkTest00002.py):** `data5 = sys.argv[5]` ← **SOURCE**
2. **Line 27 (BenchmarkTest00002.py):** `extended = manager.BenchmarkTest00002_Subclass(data5)`
   - Calls `BenchmarkTest00002_Subclass.__init__(data5)`
3. **Line 13 (BenchmarkTest00002.py):** `class BenchmarkTest00002_Subclass(BenchmarkTest00001):`
   - `BenchmarkTest00002_Subclass` inherits from `BenchmarkTest00001`
4. **Line 14 (BenchmarkTest00002.py):** `def __init__(self, data) -> None:`
   - Parameter `data` receives `data5` (tainted)
5. **Line 15 (BenchmarkTest00002.py):** `super().__init__(data)`
   - Calls `BenchmarkTest00001.__init__(data)` where `data = data5` (tainted)
6. **Line 4 (BenchmarkTest00001.py):** `def __init__(self, data):`
   - Parameter `data` receives tainted value
7. **Line 5 (BenchmarkTest00001.py):** `self.data = data`
   - Stores tainted value in `self.data`
8. **Line 6 (BenchmarkTest00001.py):** `self.process()`
   - **CRITICAL:** Since `self` is an `BenchmarkTest00002_Subclass` instance, Python's method resolution calls `BenchmarkTest00002_Subclass.process()` (the overridden method), NOT `BenchmarkTest00001.process()`
9. **Line 16 (BenchmarkTest00002.py):** `def process(self) -> None:`
   - `BenchmarkTest00002_Subclass.process()` is called (method override)
10. **Line 17 (BenchmarkTest00002.py):** `self.execute(self.data)`
    - Calls `BenchmarkTest00001.execute(self.data)` where `self.data = data5` (tainted)
11. **Line 11 (BenchmarkTest00001.py):** `def execute(self, data):`
    - Parameter `data` receives `self.data` (tainted)
12. **Line 12 (BenchmarkTest00001.py):** `sp.Popen(data, shell=True)` ← **SINK**

### Evidence:
- Inheritance: `BenchmarkTest00002_Subclass` → `BenchmarkTest00001`
- Method override: `BenchmarkTest00002_Subclass.process()` overrides `BenchmarkTest00001.process()`
- **Key insight:** When `BenchmarkTest00001.__init__` calls `self.process()` at line 6, it calls the overridden `BenchmarkTest00002_Subclass.process()` method due to Python's method resolution order
- Taint propagates through: `sys.argv[5]` → `data5` → `self.data` → `BenchmarkTest00002_Subclass.process()` → `self.execute(self.data)` → `sp.Popen(data)`

### Confidence: **HIGH** ✅
- **Reachable:** `BenchmarkTest00002_Subclass.process()` is automatically called during `BenchmarkTest00002_Subclass.__init__` via `super().__init__` → `self.process()`
- Method override ensures `BenchmarkTest00002_Subclass.process()` is invoked, not the base class method
- Direct execution path during object construction

---

## Summary of True Positives

| TP | Source | Sink | Confidence | Evidence |
|---|---|---|---|---|
| **TP1** | `sys.argv[1]` (line 5) | `sp.run` in `BenchmarkTest00001.__init__` (line 9) | **HIGH** ✅ | Direct constructor chain |
| **TP2** | `sys.argv[2]` (line 9) | `sp.Popen` in `BenchmarkTest00001.execute` (line 12) | **HIGH** ✅ | Method call chain |
| **TP3** | `sys.argv[3]` (line 22) | `sp.Popen` in `BenchmarkTest00001.execute` (line 12) | **HIGH** ✅ | Nested method call |
| **TP4** | `sys.argv[4]` (line 24) | `sp.run` in `process()` function (line 15) | **HIGH** ✅ | Direct function call |
| **TP5** | `sys.argv[5]` (line 26) | `sp.Popen` in `BenchmarkTest00001.execute` via `BenchmarkTest00002_Subclass.process()` (line 12) | **HIGH** ✅ | Method override in constructor |

### Total: **5 True Positives**
- **5 HIGH confidence** (all directly reachable in main execution)

### Key Observations:
1. All TPs originate from `BenchmarkTest00002.py` main execution (lines 20-27)
2. All sinks are in `BenchmarkTest00001.py`
3. **TP5:** Reachable via method override - `BenchmarkTest00002_Subclass.process()` is called automatically during `BenchmarkTest00002_Subclass.__init__` when `BenchmarkTest00001.__init__` calls `self.process()`. Due to method override, this calls `BenchmarkTest00002_Subclass.process()` → `execute()` → `sp.Popen`, NOT the base class `process()` → `sp.run`.
4. **Sink Distribution:**
   - **`sp.run` sinks (2 TPs):** TP1, TP4
   - **`sp.Popen` sinks (3 TPs):** TP2, TP3, TP5
5. **Flow Patterns:**
   - **Direct constructor:** TP1
   - **Method call chain:** TP2
   - **Nested method call:** TP3
   - **Direct function call:** TP4
   - **Inheritance + method override:** TP5

