"""Build deterministic, repository-free runtime archives and SHA-256 manifests."""

import argparse
import gzip
import hashlib
import io
import json
import re
import tarfile
from pathlib import Path


def package_release(root, version, output):
    """Package only explicitly selected runtime files, never local credentials."""
    if not re.fullmatch(r'\d{1,5}\.\d{1,5}\.\d{1,5}', version):
        raise ValueError('invalid release version')
    component = 'extension' if (root / 'package.json').exists() else 'sing'
    if component == 'extension':
        names = [str(path.relative_to(root)) for path in (root / 'build').rglob('*') if path.is_file()]
        names += ['src/host/sing_host.py', 'src/host/release_tools.py', 'install.sh']
        asset = 'sing-vpn-macos.tar.gz'
    else:
        names = ['bin/sing', 'share/select.py', 'proxychains/sing.conf', 'VERSION']
        asset = 'sing-macos.tar.gz'
    contents = {name: (root / name).read_bytes() for name in names}
    if component == 'sing':
        contents['VERSION'] = (version + '\n').encode()
    else:
        manifest = json.loads(contents['build/manifest.json'])
        if manifest['version'] != version:
            raise ValueError('build version does not match release; set RELEASE_VERSION when building')
        contents['build/release-info.json'] = b'{"managed":true}\n'
    contents['release.json'] = json.dumps({
        'version': version, 'component': component,
        'files': {name: hashlib.sha256(data).hexdigest() for name, data in contents.items()},
    }, sort_keys=True).encode()
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode='wb', mtime=0) as compressed, \
            tarfile.open(fileobj=compressed, mode='w') as archive:
        for name, data in sorted(contents.items()):
            member = tarfile.TarInfo(name)
            member.size = len(data)
            member.mode = 0o755 if name in ('bin/sing', 'install.sh') else 0o644
            archive.addfile(member, io.BytesIO(data))
    output.mkdir(parents=True, exist_ok=True)
    data = buffer.getvalue()
    (output / asset).write_bytes(data)
    (output / (asset + '.sha256')).write_text(hashlib.sha256(data).hexdigest() + '  ' + asset + '\n')


def main():
    """Package the current project for an explicitly supplied release version."""
    parser = argparse.ArgumentParser()
    parser.add_argument('version')
    parser.add_argument('--output', type=Path, default=Path('dist'))
    arguments = parser.parse_args()
    package_release(Path(__file__).resolve().parents[1], arguments.version, arguments.output)


if __name__ == '__main__':
    main()
