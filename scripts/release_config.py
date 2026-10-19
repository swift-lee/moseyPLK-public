"""Shared release identity for the installed KSU and Xposed components."""
import json
import re

from project_paths import ROOT

CONFIG = json.loads((ROOT / 'release.json').read_text())
VERSION = CONFIG['version']
VERSION_CODE = CONFIG['version_code']
CLIENT_ID = CONFIG['client_id']
SERVICE_ID = CONFIG['service_id']
if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', VERSION):
    raise ValueError('Invalid shared version')
if type(VERSION_CODE) is not int or VERSION_CODE <= 12:
    raise ValueError('Release code must exceed the retained component releases')
if CLIENT_ID != 'moseyPLK.client' or SERVICE_ID != 'moseyPLK.service':
    raise ValueError('Unexpected component identity')
