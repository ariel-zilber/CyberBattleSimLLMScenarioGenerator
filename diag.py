import sys
import os
print(f"PYTHONPATH: {os.environ.get('PYTHONPATH', 'not set')}")
print(f"sys.path: {sys.path}")
try:
    import pipeline
    print(f"Imported pipeline from: {pipeline.__file__}")
except ImportError as e:
    print(f"Failed to import pipeline: {e}")
