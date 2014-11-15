def _read_version_bytes():
    import os
    version_txt = os.path.sep.join(__file__.split(os.path.sep)[:-1] + ['version.txt'])
    with open(version_txt, 'rb') as fin:
        return fin.read().strip()

version_bytes = _read_version_bytes().strip()
version_str = version_bytes.decode('utf-8')
