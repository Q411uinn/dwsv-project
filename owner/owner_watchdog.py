import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from owner.owner import main
import os

# 确保监控 subs.txt 的绝对路径
SUBS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "subs.txt")

class SubsChangeHandler(FileSystemEventHandler):
    """监控 subs.txt 文件变化"""
    def on_modified(self, event):
        if os.path.abspath(event.src_path) == SUBS_FILE:
            print(f"⚠️ 检测到 {SUBS_FILE} 文件变化，触发 DNS 更新...")
            try:
                main()
            except Exception as e:
                print(f"❌ 更新失败: {e}")
    # 监听文件移动/重建
    def on_moved(self, event):
        self.on_modified(event)
    def on_created(self, event):
        self.on_modified(event)

if __name__ == "__main__":
    path_to_watch = os.path.dirname(SUBS_FILE)
    event_handler = SubsChangeHandler()
    observer = Observer()
    observer.schedule(event_handler, path=path_to_watch, recursive=False)
    observer.start()
    print(f"👀 监控 {SUBS_FILE} 变化中... 按 Ctrl+C 停止")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
