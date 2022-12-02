from cx_Freeze import setup, Executable

files = ["core", "color_mask_threshold.txt", "data","classes.names", "Login.ini", "aivcMonitor","lib"]
exFiles = ["matplotlib.tests", "numpy.random._examples"]

target = Executable(
    script="AIVC.py",
    base=None,
    icon='utils/icons/TG_icon.ico'
)

setup(
    name = "AIVC",
    version = "2.3.70.8",
    description = "AIVC 4",
    author = "Syafi'i",
    options = {'build_exe' : {'include_files' : files , 'excludes' : exFiles}},
    executables = [target]
)
