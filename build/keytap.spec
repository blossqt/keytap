# PyInstaller spec for Keytap - built by build_app.ps1
import os

project = os.path.abspath(os.path.join(SPECPATH, '..'))
app_dir = os.path.join(project, 'app')

# comtypes writes its wrappers for UI Automation the first time it is asked
# (build_app.ps1 asks before packaging); a packaged exe cannot write them, so
# they go in ready-made.
hiddenimports = ['keytap', 'keytap.app', 'keytap.focus', 'comtypes', 'comtypes.client',
                 'comtypes.gen', 'comtypes.gen.UIAutomationClient',
                 'comtypes.gen._944DE083_8FB8_45CF_BCB7_C477ACB2F897_0_1_0']

# Qt's plugins, named here rather than left to PyInstaller's Qt hook. The hook
# drops any plugin whose Qt libraries it finds by a second path - and a build
# run from inside a packaged app, such as the Claude desktop app, sees AppData
# by two paths. Grabbit lost every plugin that way once, qwindows.dll included,
# and the exe it made could not open a window.
import PySide6
qt_plugins = os.path.join(os.path.dirname(PySide6.__file__), 'plugins')
qt_plugin_binaries = [
    (os.path.join(qt_plugins, kind, name), os.path.join('PySide6', 'plugins', kind))
    for kind in ('platforms', 'imageformats', 'iconengines', 'styles', 'generic')
    if os.path.isdir(os.path.join(qt_plugins, kind))
    for name in sorted(os.listdir(os.path.join(qt_plugins, kind)))
    # qpdf.dll needs Qt's PDF library, which Keytap has no use for.
    if name.lower().endswith('.dll') and name.lower() != 'qpdf.dll'
]
if not any(dest.endswith('platforms') and src.endswith('qwindows.dll') for src, dest in qt_plugin_binaries):
    raise SystemExit('Qt\'s Windows platform plugin (qwindows.dll) was not found - the exe could not start')

a = Analysis(
    [os.path.join(app_dir, 'main.py')],
    pathex=[app_dir],
    binaries=qt_plugin_binaries,
    datas=[],
    hiddenimports=hiddenimports,
    hookspath=[],
    excludes=[
        'tkinter', 'unittest', 'pydoc_data', 'lib2to3', 'test',
        'PySide6.QtQml', 'PySide6.QtQuick', 'PySide6.QtQuickWidgets',
        'PySide6.QtDesigner', 'PySide6.QtHelp', 'PySide6.QtTest', 'PySide6.QtSql',
        'PySide6.QtOpenGL', 'PySide6.QtPdf', 'PySide6.QtPdfWidgets', 'PySide6.QtMultimedia',
        'PySide6.QtConcurrent', 'PySide6.QtDBus', 'PySide6.QtXml',
    ],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='Keytap',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    # Windowed by default; set KEYTAP_CONSOLE=1 to build a console variant
    # that prints tracebacks, which is the only way to debug startup failures.
    console=os.environ.get('KEYTAP_CONSOLE') == '1',
    disable_windowed_traceback=False,
    icon=os.path.join(SPECPATH, 'keytap.ico'),
    version=os.path.join(SPECPATH, 'version_info.txt'),
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name='Keytap',
)
