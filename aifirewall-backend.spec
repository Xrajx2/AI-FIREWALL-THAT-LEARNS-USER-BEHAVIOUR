# -*- mode: python ; coding: utf-8 -*-
import os
import sys

datas = []
if os.path.exists('backend/security/malware_signatures.json'):
    datas.append(('backend/security/malware_signatures.json', 'backend/security'))

# aifirewall.db is intentionally excluded - DB is auto-created in %APPDATA%\AIFirewall

a = Analysis(
    ['backend/main.py'],
    pathex=['.', 'backend'],
    binaries=[],
    datas=datas,
    hiddenimports=[
        'uvicorn',
        'uvicorn.logging',
        'uvicorn.loops',
        'uvicorn.loops.auto',
        'uvicorn.protocols',
        'uvicorn.protocols.http',
        'uvicorn.protocols.http.auto',
        'uvicorn.protocols.websockets',
        'uvicorn.protocols.websockets.auto',
        'uvicorn.lifespan',
        'uvicorn.lifespan.on',
        'passlib.handlers.bcrypt',
        'bcrypt',
        'sklearn',
        'sklearn.ensemble',
        'sklearn.cluster',
        'sklearn.neighbors',
        'sklearn.tree',
        'sklearn.utils._typedefs',
        'psutil',
        'watchdog',
        'email_validator',
        'sqlalchemy',
        'sqlalchemy.dialects.sqlite',
        'jose',
        'jose.jwt',
        'win32crypt',
        'cryptography',
        'cryptography.fernet',
        'requests',
        'fastapi',
        'starlette',
        'pydantic',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='aifirewall-backend',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='assets/icon.ico' if os.path.exists('assets/icon.ico') else None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='aifirewall-backend',
)
