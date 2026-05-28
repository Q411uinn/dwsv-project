# benchmarks/benchmark_baseline_e2e.py
import time
import statistics
import requests

URL = "http://127.0.0.1:5001/"
REPEAT = 50

times = []

for _ in range(REPEAT):
    t0 = time.perf_counter()
    r = requests.get(URL, timeout=3)
    r.raise_for_status()
    times.append((time.perf_counter() - t0) * 1000)

print("普通服务基线端到端耗时")
print(f"avg(ms): {statistics.mean(times):.3f}")
print(f"median(ms): {statistics.median(times):.3f}")
print(f"std(ms): {statistics.pstdev(times):.3f}")
