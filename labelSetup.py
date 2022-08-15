import sys
from cx_Freeze import setup, Executable

# Dependencies are automatically detected, but it might need fine tuning.
#build_exe_options = {"packages": ["pyqt5","numpy", "PIL"], "include_files": ["yolov3_glove_5class_last.weights","data"],  "excludes": ["matplotlib.tests", "numpy.random._examples"]}
build_exe_options = {"packages": ["pyqt5", "six", "mkl"], "excludes": ["matplotlib.tests", "numpy.random._examples"],\
 "include_files": ["data","classes.names","lib\\AIVC.pem"]}

# GUI applications require a different base on Windows (the default is for a
# console application).
base = None
# if sys.platform == "win32":
#     base = "Win32GUI"

setup(  name = "TGAITrainer",
        version = "2.0.1",
        description = "Yolov3 Labelling & Training",
        options = {"build_exe": build_exe_options},
        executables = [Executable("labelImg.py", base=base, targetName="TGAITrainer.exe", icon='utils/icons/TGAITrainer.ico')])
