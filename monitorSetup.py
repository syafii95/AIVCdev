import sys
from cx_Freeze import setup, Executable

# Dependencies are automatically detected, but it might need fine tuning.

# GUI applications require a different base on Windows (the default is for a
# console application).
base = None

setup(  name = "AIVC_Monitor",
        version = "0.1",
        description = "Yolov3 Labelling & Training",
        executables = [Executable("aivcMonitor.py", base=base, targetName="AIVC_Monitor.exe")])
