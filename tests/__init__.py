import os
import sys

# Ensure worker/ and root directories are in sys.path for test discovery
worker_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "worker"))
if worker_dir not in sys.path:
    sys.path.insert(0, worker_dir)
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)
