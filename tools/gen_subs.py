import os

n = 1000

# 获取当前文件目录
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# 拼接到 owner/subs.txt
subs_path = os.path.join(BASE_DIR, "..", "owner", "subs.txt")

# 规范路径
subs_path = os.path.normpath(subs_path)

with open(subs_path, "w") as f:
    for i in range(n):
        f.write(f"sub{i}\n")

print(f"生成 {n} 个子域 -> {subs_path}")

