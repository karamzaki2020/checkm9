import hashlib, os, platform, cStringIO, tarfile

class VersionConfig:
    def __init__(self, version, bottle, bottle_sha256, dylib_patches, dylib_sha256):
        self.version = version
        self.bottle = bottle
        self.bottle_sha256 = bottle_sha256
        self.dylib_patches = dylib_patches
        self.dylib_sha256 = dylib_sha256

configs = [
    VersionConfig(
        version='10.14',
        bottle='libusb-1.0.22.mojave.bottle',
        bottle_sha256='6accd1dfe6e66c30aac925ad674e9c7a49b752bcf94561e9e2d397ce199504ff',
        dylib_patches=[(0x9fd1, 'E995000000'.decode('hex'))],
        dylib_sha256='34d4c0ca921a31f93f3960575f9693cdb9fc5cbd4167393eedfb9b2ba7f7d9d5'),
    VersionConfig(
        version='10.13',
        bottle='libusb-1.0.22.high_sierra.bottle',
        bottle_sha256='7b1fd96a5129620d1bbf049c69c7742ecad450de139b9196bf9e995a752b2302',
        dylib_patches=[(0x99fb, 'E97F000000'.decode('hex'))],
        dylib_sha256='7bd49a3a9955fc20752433f944f61d59d5ec9b69d25dcfab1671f3c92339c4f9'),
    VersionConfig(
        version='10.12',
        bottle='libusb-1.0.22.sierra.bottle',
        bottle_sha256='7f2b65d09525c432a96e46699a1449bab36503f45f16d6e0d9f42be6b1ef55cf',
        dylib_patches=[(0x99fb, 'E97F000000'.decode('hex'))],
        dylib_sha256='0d396945a96fa0457cb6c200f956c9b0d5f236729ef1e2cff34cd312f9cfc7ba'),
    VersionConfig(
        version='10.11',
        bottle='libusb-1.0.22.el_capitan.bottle',
        bottle_sha256='33575c9f56bc0d57bf995a21e40be019d5c269b432939416be9f24c5921bbb29',
        dylib_patches=[(0x9917, 'E956010000'.decode('hex'))],
        dylib_sha256='7ae949e0e9730bf9de49bb534a9ee42eb301a2f6ba6cc199229ce9bf79a6ba07'),
    VersionConfig(
        version='10.10',
        bottle='libusb-1.0.21.yosemite.bottle',
        bottle_sha256='9931059f7595ed973d993dd92995e1732c240a79f4f7a92e5d5c7dfe27d49941',
        dylib_patches=[],
        dylib_sha256='9e99265251d119f3422a760cf3472ecc46b7c3d22599600905dd5595a1ec146a'),
    VersionConfig(
        version='10.9',
        bottle='libusb-1.0.20.mavericks.bottle.1',
        bottle_sha256='5a475e2ca93996e51b994d1ea323e915c91d9463e5b23b45203acb69edf69991',
        dylib_patches=[],
        dylib_sha256='9f21fc0af0c7b04e7db999e1fc66ea9dbc31299096c69416140152d70139c316'),
    VersionConfig(
        version='10.9',
        bottle='libusb-1.0.19.mountain_lion.bottle.1',
        bottle_sha256='d5c4bd99b359a9319d49e06b6b13fc529f91a5bd61ce5a9ff14c291b44b676da',
        dylib_patches=[],
        dylib_sha256='0490900ca9ff92d37c310a09f9bd29aaa97143cf96b35d94b170617ec9d127bb'),
]

dir = os.path.dirname(__file__)
BOTTLE_PATH_FORMAT = os.path.join(dir, 'bottles', '%s.tar.gz')
DYLIB_PATH_FORMAT = os.path.join(dir, '%s.dylib')
DYLIB_NAME = 'libusb-1.0.0.dylib'

def apply_patches(binary, patches):
    for (offset, data) in patches:
        binary = binary[:offset] + data + binary[offset + len(data):]
    return binary

def libusb1_path_internal():
    version = platform.mac_ver()[0]
    # HACK to support macOS 10.15
    if version == '10.15':
        version = '10.14'
    if version == '':
        # We're not running on a Mac.
        return None

    for config in configs:
        if version.startswith(config.version):
            path = DYLIB_PATH_FORMAT % config.bottle
            try:
                f = open(path, 'rb')
                dylib = f.read()
                f.close()
                if hashlib.sha256(dylib).hexdigest() == config.dylib_sha256:
                    return path
                print 'WARNING: SHA256 hash of existing dylib does not match.'
            except IOError:
                pass

            f = open(BOTTLE_PATH_FORMAT % config.bottle, 'rb')
            bottle = f.read()
            f.close()
            if hashlib.sha256(bottle).hexdigest() != config.bottle_sha256:
                print 'ERROR: SHA256 hash of bottle does not match.'
                sys.exit(1)

            tar = tarfile.open(fileobj=cStringIO.StringIO(bottle))
            for member in tar.getmembers():
                if member.name.endswith(DYLIB_NAME):
                    patched_dylib = apply_patches(tar.extractfile(member.name).read(), config.dylib_patches)
                    if hashlib.sha256(patched_dylib).hexdigest() != config.dylib_sha256:
                        print 'ERROR: SHA256 hash of new dylib does not match.'
                        sys.exit(1)
                    f = open(path, 'wb')
                    f.write(patched_dylib)
                    f.close()
                    return path

    # No match found.
    return None

cached_path = libusb1_path_internal()

def libusb1_path():
    return cached_path
