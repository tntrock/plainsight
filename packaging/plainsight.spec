# PyInstaller spec: builds dist/PlainSight.exe (one file, console app).
# Usage: pyinstaller packaging/plainsight.spec
import re
from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

ROOT = Path(SPECPATH).parent
PKG = ROOT / "plainsight"

# Windows "Details" tab version resource, generated from plainsight.__version__.
VERSION = re.search(r'__version__ = "([^"]+)"', (PKG / "__init__.py").read_text(encoding="utf-8")).group(1)
nums = tuple(int(x) for x in re.findall(r"\d+", VERSION)[:3]) + (0,)
VERSION_FILE = Path(workpath) / "version_info.txt"
VERSION_FILE.parent.mkdir(parents=True, exist_ok=True)
VERSION_FILE.write_text(f"""VSVersionInfo(
  ffi=FixedFileInfo(filevers={nums}, prodvers={nums}),
  kids=[
    StringFileInfo([StringTable('040404b0', [
      StringStruct('CompanyName', 'PlainSight contributors'),
      StringStruct('FileDescription', 'PlainSight 明文透視 - educational plaintext traffic dashboard'),
      StringStruct('FileVersion', '{VERSION}'),
      StringStruct('InternalName', 'PlainSight'),
      StringStruct('LegalCopyright', 'MIT License'),
      StringStruct('OriginalFilename', 'PlainSight.exe'),
      StringStruct('ProductName', 'PlainSight'),
      StringStruct('ProductVersion', '{VERSION}')])]),
    VarFileInfo([VarStruct('Translation', [0x0404, 1200])])
  ]
)
""", encoding="utf-8")

a = Analysis(
    [str(ROOT / "packaging" / "launcher.py")],
    pathex=[str(ROOT)],
    datas=[
        (str(PKG / "web"), "plainsight/web"),
        # mitmdump loads the addon from a real .py file on disk.
        (str(PKG / "mitm_addon.py"), "plainsight"),
    ],
    # Scapy imports its layers and platform backends dynamically.
    hiddenimports=collect_submodules("scapy.layers") + collect_submodules("scapy.arch"),
    excludes=["tkinter", "matplotlib", "IPython", "numpy", "PIL", "pytest", "playwright"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="PlainSight",
    icon=str(ROOT / "packaging" / "plainsight.ico"),
    version=str(VERSION_FILE),
    console=True,
    upx=False,  # UPX-packed binaries trigger more antivirus false positives
)
