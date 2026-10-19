"""Pinned host-only Gradle toolchain. Third-party inputs stay in ignored assets."""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import tarfile
import urllib.request
import zipfile

from project_paths import ASSETS, ROOT

TOOLS = ASSETS / 'tools/client-ui'
GRADLE_VERSION = '9.6.1'
JDK_VERSION = '21.0.12.1+1'
INPUTS = {
    'gradle-9.6.1-bin.zip': ('9c0f7faeeb306cb14e4279a3e084ca6b596894089a0638e68a07c945a32c9e14',
        'https://services.gradle.org/distributions/gradle-9.6.1-bin.zip'),
    'OpenJDK21U-jdk_x64_linux_hotspot_21.0.12.1_1.tar.gz': (
        'ce79869e1307ed8ee1e2baa86a412b1eb5b75d10a01006d788a6f968bcfaee94',
        'https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.12.1%2B1/OpenJDK21U-jdk_x64_linux_hotspot_21.0.12.1_1.tar.gz'),
    'platform-37.0_r02.zip': ('840b23e827f96e64aea4c89a1194aac3dc5f6bad37edb231c5c795d890330e8d',
        'https://dl.google.com/android/repository/platform-37.0_r02.zip'),
    'build-tools_r37_linux.zip': ('01af179347cbcd9c208b7f8171f7b21f6dd1d2f85bcd15e88caa51d5d7b86060',
        'https://dl.google.com/android/repository/build-tools_r37_linux.zip'),
}


def prepare(*, fetch=False, proxy=None):
    downloads = TOOLS / 'downloads'
    downloads.mkdir(parents=True, exist_ok=True)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler(
        {'http': proxy, 'https': proxy} if proxy else {}))
    for name, (expected, url) in INPUTS.items():
        path = downloads / name
        if not path.exists() and fetch:
            temporary = path.with_suffix(path.suffix + '.partial')
            with opener.open(url, timeout=300) as response, temporary.open('wb') as output:
                shutil.copyfileobj(response, output)
            if hashlib.sha256(temporary.read_bytes()).hexdigest() != expected:
                raise ValueError('Downloaded tool checksum mismatch: ' + name)
            temporary.replace(path)
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError('Missing or modified pinned tool archive: ' + name)
    layouts = {
        'gradle-9.6.1-bin.zip': (TOOLS, 'gradle-9.6.1', 'gradle-9.6.1'),
        'platform-37.0_r02.zip': (TOOLS / 'sdk/platforms', 'android-37.0', 'android-37.0'),
        'build-tools_r37_linux.zip': (TOOLS / 'sdk/build-tools', 'android-37.0', '37.0.0'),
    }
    for name, (destination, root, final) in layouts.items():
        target = destination / final
        if target.is_dir():
            continue
        destination.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(downloads / name) as archive:
            for info in archive.infolist():
                relative = Path(info.filename)
                if relative.is_absolute() or '..' in relative.parts or relative.parts[0] != root:
                    raise ValueError('Unsafe tool archive member')
                archive.extract(info, destination)
                if not info.is_dir() and (info.external_attr >> 16) & 0o111:
                    (destination / info.filename).chmod(0o755)
        if root != final:
            (destination / root).rename(target)
    jdk = TOOLS / ('jdk-' + JDK_VERSION)
    if not jdk.is_dir():
        with tarfile.open(downloads / 'OpenJDK21U-jdk_x64_linux_hotspot_21.0.12.1_1.tar.gz') as archive:
            archive.extractall(TOOLS, filter='data')
    if not (jdk / 'bin/java').is_file():
        raise ValueError('Pinned JDK layout missing')
    # The platform ZIP has source.properties but no package.xml. The legacy
    # importer cannot parse the new decimal API level (37.0), so describe the
    # already verified/extracted local package with the current SDK schema.
    # This neither downloads an SDK implicitly nor writes license acceptances.
    platform = TOOLS / 'sdk/platforms/android-37.0'
    (platform / 'package.xml').write_text('''<?xml version="1.0" encoding="UTF-8"?>
<repository xmlns="http://schemas.android.com/repository/android/common/02"
 xmlns:sdk="http://schemas.android.com/sdk/android/repo/repository2/04"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
 <localPackage xmlns="" path="platforms;android-37.0" obsolete="false">
  <type-details xsi:type="sdk:platformDetailsType">
   <api-level>37.0</api-level><extension-level>22</extension-level>
   <base-extension>true</base-extension><layoutlib api="15"/>
  </type-details>
  <revision><major>2</major></revision>
  <display-name>Android SDK Platform 37.0</display-name>
 </localPackage>
</repository>
''')
    return TOOLS / 'gradle-9.6.1/bin/gradle', jdk, TOOLS / 'sdk'


def environment(jdk, sdk):
    env = os.environ.copy()
    env.update(JAVA_HOME=str(jdk), ANDROID_HOME=str(sdk), ANDROID_SDK_ROOT=str(sdk),
               GRADLE_USER_HOME=str(TOOLS / 'gradle-home'))
    env['PATH'] = str(jdk / 'bin') + os.pathsep + env.get('PATH', '')
    return env


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fetch', action='store_true')
    parser.add_argument('--proxy', help='Optional HTTP proxy URL for explicit fetch only')
    args = parser.parse_args()
    for path in prepare(fetch=args.fetch, proxy=args.proxy):
        print(path.relative_to(ROOT))
