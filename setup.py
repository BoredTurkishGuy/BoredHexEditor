from cx_Freeze import setup, Executable
import sys

base = None
if sys.platform == "win32":
    base = "Win32GUI"

buildOptions = {
    "include_files": [
        (
            "C:/Users/hp/AppData/Local/Programs/Python/Python311/Lib/site-packages/capstone/lib/capstone.dll",
            "capstone/lib/capstone.dll"
        )
    ]
}

executables = [
    Executable("BoredEditor.py", base=base)
]

setup(
    name="BoredEditor",
    version="1.0",
    description="Hex / Assembly editor, made in Python.",
    options={"build_exe": buildOptions},
    executables=executables
)
