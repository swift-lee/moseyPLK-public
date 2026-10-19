#!/usr/bin/env python3
"""Rebuild compact evidence from already extracted firmware; does not modify firmware."""
from pathlib import Path
import hashlib
import json
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[2] / 'moseyPLK-assets/research'
EX = ROOT / 'extracted'
OUT = ROOT / 'evidence'
OUT.mkdir(parents=True, exist_ok=True)
def digest(p):
    with p.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()

paths = [
    'system_ext/priv-app/MoseyApp/MoseyApp.apk',
    'system_ext/etc/permissions/privapp-permissions-com.google.android.mosey.xml',
    'system_ext/etc/default-permissions/default-permissions-com.google.android.mosey.xml',
    'odm/bin/mosey_server', 'odm/lib64/libmosey_daemon_ffi.so',
    'odm/etc/init/mosey.rc', 'odm/etc/vintf/manifest/manifest_mosey.xml',
    'system_ext/etc/selinux/system_ext_seapp_contexts',
    'system_ext/etc/sysconfig/hidden-api-whitelist-ext.xml',
    'system/system/etc/vintf/compatibility_matrix.device.xml',
    'my_product/priv-app/GmsCore/GmsCore.apk',
    'my_product/etc/config/app_v2.xml', 'my_stock/etc/config/app_v2.xml',
    'vendor/etc/selinux/vendor_sepolicy.cil',
    'vendor/etc/selinux/vendor_file_contexts',
    'vendor/etc/selinux/vendor_service_contexts',
    'system_ext/etc/selinux/system_ext_sepolicy.cil',
    'vendor_dlkm/lib/modules/wonder.ko', 'vendor_dlkm/lib/modules/cnss2.ko',
    'vendor_dlkm/lib/modules/qca_cld3_peach_v2.ko',
]
rows = []
for rel in paths:
    row = {'path': rel}
    for osname in ['ColorOS', 'OxygenOS']:
        p = EX / osname / rel
        row[osname] = {'size': p.stat().st_size, 'sha256': digest(p)} if p.is_file() else None
    row['same'] = bool(row['ColorOS'] and row['ColorOS'] == row['OxygenOS'])
    rows.append(row)
(OUT / 'component-comparison.json').write_text(json.dumps(rows, indent=2))

def elf_sections(p):
    data = p.read_bytes()
    assert data[:6] == b'\x7fELF\x02\x01', 'Expected ELF64 little endian'
    offset = struct.unpack_from('<Q', data, 40)[0]
    size, count, string_index = struct.unpack_from('<HHH', data, 58)
    headers = [struct.unpack_from('<IIQQQQIIQQ', data, offset + i * size) for i in range(count)]
    h = headers[string_index]
    strings = data[h[4]:h[4]+h[5]]
    return {strings[h[0]:].split(b'\0')[0].decode(): data[h[4]:h[4]+h[5]]
            for h in headers if h[1] != 8}

drivers = []
for name in ['wonder', 'cnss2', 'qca_cld3_peach_v2', 'qca_cld3_wcn7750', 'qca_cld3_kiwi_v2']:
    row = {'module': name}
    for osname in ['ColorOS', 'OxygenOS']:
        p = EX / osname / 'vendor_dlkm/lib/modules' / (name + '.ko')
        sections = elf_sections(p)
        for sec in ['.text', '.rodata', '__versions', '.modinfo']:
            row[osname + sec] = hashlib.sha256(sections[sec]).hexdigest() if sec in sections else None
        (OUT / f'{osname}-{name}-modinfo.txt').write_text(
            subprocess.check_output(['readelf', '-p', '.modinfo', str(p)], text=True))
    drivers.append(row)
(OUT / 'driver-sections.json').write_text(json.dumps(drivers, indent=2))

for osname in ['ColorOS', 'OxygenOS']:
    files = sorted(str(p.relative_to(EX / osname)) for p in (EX / osname).rglob('*') if p.is_file())
    (OUT / f'{osname}-file-list.txt').write_text('\n'.join(files) + '\n')
print('Wrote component-comparison.json, driver-sections.json, modinfo and file inventories.')
