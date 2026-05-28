import time
import statistics
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

URL = "https://www.example.test:8443/"
REPEAT = 50

times = []

for _ in range(REPEAT):
    t0 = time.perf_counter()
    r = requests.get(URL, verify=False, timeout=5)
    r.raise_for_status()
    times.append((time.perf_counter() - t0) * 1000)

print("普通通配符 HTTPS 基线")
print(f"avg(ms):    {statistics.mean(times):.3f}")
print(f"median(ms): {statistics.median(times):.3f}")
print(f"std(ms):    {statistics.pstdev(times):.3f}")
