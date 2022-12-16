import os
import shutil 
import sys
from cx_Freeze import setup, Executable

build_exe_options = {"packages": ["MvImport","pyqt5","tensorboard.summary","cv2","tensorflow_core","wrapt","absl","gast",\
"astor","termcolor","opt_einsum","google.protobuf","tensorflow_estimator","matplotlib","os", "tensorflow", "numpy", "PIL"],\
 "include_files": ["core", "color_mask_threshold.txt", "data","classes.names", "Login.ini", "aivcMonitor","lib"],  \
 "excludes": ["matplotlib.tests", "numpy.random._examples"]}

# GUI applications require a different base on Windows (the default is for a
# console application).
base = None
# if sys.platform == "win32":
#     base = "Win32GUI"

setup(  name = "AIVC",
        version = "2.3.70.2",
        description = "AIVC 4",
        author = "Syafii",
        options = {"build_exe": build_exe_options},
        executables = [Executable("AIVC.py", base=base, icon='utils/icons/TG_icon.ico')])

def copyFile():
    paths = os.path.abspath(os.getcwd())
    listfile = ["pyqtgraph","pyqtgraph-0.11.1.dist-info"]
    for j in range (len(listfile)):
        src = f'{paths}/{listfile[j]}'
        libPath = f'{paths}/build/exe.win-amd64-3.6/lib/{listfile[j]}'
        src = src.replace("\\", "/")
        libPath = libPath.replace("\\", "/")
        if not os.path.exists(libPath):
            shutil.copytree(src, libPath) 
            print(f'Path not exist. Create new one: {libPath}')
        else:
            print(f'Path exist. Replace with {libPath}')
            shutil.rmtree(libPath)
            shutil.copytree(src, libPath)

copyFile()