# -*- mode: python ; coding: utf-8 -*-


block_cipher = None

added_files = [
    ('config', 'config'),
    ('ui/resource', 'ui/resource'),
    ('ui/tools/tools.html', 'ui/tools/'),
    ('ui/agreement.html', 'ui/'),
    ('scripts', 'scripts'),
    ('tools/hydra', 'tools/hydra'),
    ('tools/masscan.exe', 'tools/'),
    ('tools/GitHack/dist/GitHack.exe', 'tools/GitHack/'),
    ('tools/iis_shortname_scanner/dist/iis_shortname_scan.exe', 'tools/iis_shortname_scanner/'),
    ('tools/ds_store_exp/dist/ds_store_exp.exe', 'tools/ds_store_exp/'),
    ('tools/idea_exploit/dist/idea_exp.exe', 'tools/idea_exploit/'),
    ('tools/subDomainsBrute/dist/subDomainsBrute', 'tools/subDomainsBrute'),
    ('tools/swagger-exp/dist/swagger-exp.exe', 'tools/swagger-exp'),
    ('tools/swagger-exp/static', 'tools/swagger-exp/static'),
    ('tools/swagger-exp/index.html', 'tools/swagger-exp/'),
    ('tools/swagger-exp/README.md', 'tools/swagger-exp/'),
    ('tools/ncrack', 'tools/ncrack'),
    ('tools/nmap', 'tools/nmap'),
    ('lib/is-http.nse', 'lib/'),

]

hidden_imports=['motor.motor_asyncio', 'aiohttp_xmlrpc.client', 'aioredis', 'etcd3', 'protobuf', 'ds-store',
                'lib.poc.process', 'lib.poc.axfr_client']

a = Analysis(
    ['EasyPen.py'],
    pathex=[],
    binaries=[],
    datas=added_files,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='EasyPen',
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
    icon='ui/resource/EasyPen.png',
)
coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='EasyPen',
)
