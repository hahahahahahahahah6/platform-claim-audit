import builtins
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from platform_claim_audit.core import audit, WINDOWS, POSIX, RULE
from platform_claim_audit.__main__ import main

FIXTURES = Path(__file__).parent / 'fixtures'


class AuditTests(unittest.TestCase):
    def project(self, docs='Cross-platform', code='pass', extra=None):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / 'README.md').write_text(docs)
        if code is not None:
            (root / 'app.py').write_text(code)
        for name, content in (extra or {}).items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        return root

    def cli(self, *args):
        output, error = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            try:
                code = main(list(map(str, args)))
            except SystemExit as exc:
                code = exc.code
        return code, output.getvalue(), error.getvalue()

    def test_good(self):
        self.assertEqual(self.cli(FIXTURES / 'good')[0], 0)

    def test_bad(self):
        code, out, _ = self.cli(FIXTURES / 'bad', '--json')
        self.assertEqual(code, 2)
        result = json.loads(out)
        self.assertEqual([(f['claim'], f['api'], f['code_line']) for f in result['findings']], [('linux', 'winreg', 1), ('macos', 'winreg', 1), ('windows', 'fcntl', 2)])
        self.assertEqual(result['status'], 'FAIL')

    def test_version(self):
        self.assertEqual(self.cli('--version')[:2], (0, '0.1.0\n'))

    def test_threshold(self):
        self.assertEqual(self.cli(FIXTURES / 'bad', '--fail-on', 'HIGH')[0], 2)

    def test_ignore(self):
        self.assertEqual(self.cli(FIXTURES / 'bad', '--fail-on', 'HIGH', '--ignore', 'other,' + RULE)[0], 0)

    def test_invalid_threshold(self):
        self.assertEqual(self.cli('--fail-on', 'LOW')[0], 1)

    def test_missing_directory(self):
        self.assertEqual(self.cli('/does-not-exist')[0], 1)

    def test_unknown_flag(self):
        self.assertEqual(self.cli('--no-such-flag')[0], 1)

    def test_default_directory(self):
        import os
        root = self.project()
        old = os.getcwd()
        try:
            os.chdir(root)
            self.assertEqual(self.cli()[0], 0)
        finally:
            os.chdir(old)

    def test_verbose(self):
        self.assertIn('OK platform windows', self.cli(FIXTURES / 'good', '--verbose')[1])

    def test_deterministic(self):
        self.assertEqual(self.cli(FIXTURES / 'bad', '--json'), self.cli(FIXTURES / 'bad', '--json'))

    def test_no_source(self):
        result = audit(self.project(code=None))
        self.assertEqual(len(result['findings']), 3)
        self.assertEqual(result['verified_claims'], [])

    def test_no_claims(self):
        self.assertEqual(audit(self.project('A tool', 'import winreg'))['status'], 'PASS')

    def test_malformed(self):
        self.assertEqual(audit(self.project(code='def broken('))['status'], 'PASS')

    def test_never_opens_env(self):
        root = self.project()
        (root / '.env').touch()
        original = io.open
        def checked(file, *args, **kwargs):
            if isinstance(file, (str, Path)):
                self.assertNotEqual(Path(file).name, '.env')
            return original(file, *args, **kwargs)
        with patch('io.open', checked), patch('builtins.open', checked):
            self.assertEqual(audit(root)['status'], 'PASS')

    def test_first_provenance(self):
        root = self.project('Windows support\nWindows support', 'import fcntl\nimport fcntl', {'docs/a.md': 'Windows support'})
        finding = audit(root)['findings'][0]
        self.assertEqual((finding['docs_file'], finding['docs_line'], finding['code_line']), ('README.md', 1, 1))

    def test_docs_only(self):
        self.assertEqual(audit(self.project('Nothing', 'import fcntl', {'other.md': 'Windows support'}))['status'], 'PASS')

    def test_docs_nested(self):
        self.assertEqual(len(audit(self.project('', 'import fcntl', {'docs/deep/a.md': 'Windows support'}))['findings']), 1)

    def test_else(self):
        self.assertEqual(audit(self.project(code="import sys\nif sys.platform == 'win32':\n    pass\nelse:\n    import fcntl"))['status'], 'PASS')

    def test_wrong_guard(self):
        self.assertEqual(audit(self.project(code="import sys\nif sys.platform == 'win32':\n    import fcntl"))['findings'][0]['claim'], 'windows')

    def test_bare_attribute(self):
        self.assertEqual(len(audit(self.project(code='import os\nx = os.startfile'))['findings']), 2)

    def test_from_alias(self):
        self.assertEqual(len(audit(self.project(code='from os import fork as spawn\nspawn()'))['findings']), 1)

    def test_alias_guard(self):
        self.assertEqual(audit(self.project(code="import sys as s\nif s.platform == 'win32':\n    import winreg"))['status'], 'PASS')


def add(name, function):
    setattr(AuditTests, 'test_' + name, function)


for api in sorted(WINDOWS | POSIX):
    def row(self, api=api):
        module = api.split('.')[0]
        code = 'import ' + module
        if '.' in api:
            code += '\n' + api + '.foo' if api == 'ctypes.windll' else '\n' + api
        expected = 2 if api in WINDOWS else 1
        self.assertEqual(len(audit(self.project(code=code))['findings']), expected)
        guard = "sys.platform == 'win32'" if api in WINDOWS else "os.name == 'posix'"
        guarded = 'import sys\nimport os\nif ' + guard + ':\n' + '\n'.join('    ' + line for line in code.splitlines())
        self.assertEqual(audit(self.project(code=guarded))['status'], 'PASS')
    add('table_' + api.replace('.', '_'), row)

for index, prose in enumerate(['cross-platform', 'Cross Platform', 'works on Windows, macOS and Linux', 'runs on win32, osx and linux', 'supports WIN, MAC and Linux', 'support for Windows macOS Linux', 'supported on Windows macOS Linux']):
    def variant(self, prose=prose):
        self.assertEqual(audit(self.project(prose))['verified_claims'], ['linux', 'macos', 'windows'])
    add('prose_' + str(index), variant)

for index, prose in enumerate(['Windows support', 'Windows only', 'Windows-only', 'requires Windows', 'Windows required']):
    def single(self, prose=prose):
        self.assertEqual(audit(self.project(prose, 'import winreg'))['verified_claims'], ['windows'])
    add('single_' + str(index), single)

for index, negative in enumerate(['not supported on Windows', 'no Windows support', 'Windows not supported', 'does not support Windows']):
    def removal(self, negative=negative):
        self.assertEqual(audit(self.project('Cross-platform\n' + negative, 'import fcntl'))['status'], 'PASS')
    add('negative_' + str(index), removal)

for index, test in enumerate(["sys.platform.startswith('win')", "sys.platform == 'cygwin'", "os.name == 'nt'", "'win32' == sys.platform"]):
    def guard(self, test=test):
        self.assertEqual(audit(self.project(code='import sys\nimport os\nif ' + test + ':\n    import winreg'))['status'], 'PASS')
    add('guard_' + str(index), guard)

for index, test in enumerate(["not sys.platform == 'win32'", "sys.platform == 'win32' and enabled", 'enabled', "sys.platform == 'unknown'"]):
    def unresolved(self, test=test):
        self.assertEqual(len(audit(self.project(code='import sys\nif ' + test + ':\n    import winreg'))['findings']), 2)
    add('unresolved_' + str(index), unresolved)

for index, handler in enumerate(['ImportError', '(ImportError, OSError)', '']):
    def fallback(self, handler=handler):
        self.assertEqual(audit(self.project(code='try:\n    import winreg\nexcept ' + handler + ':\n    pass'))['status'], 'PASS')
    add('fallback_' + str(index), fallback)

for index, filename in enumerate(['tests/a.py', 'sub/tests/a.py', 'test_app.py', 'app_test.py', 'fixtures/a.py', 'docs/a.py']):
    def excluded(self, filename=filename):
        self.assertEqual(audit(self.project(extra={filename: 'import winreg'}))['status'], 'PASS')
    add('excluded_' + str(index), excluded)

for index, prose in enumerate(['```python\nWindows support\n```', '~~~\nCross-platform\n~~~', 'FreeBSD and Android support']):
    def excluded_prose(self, prose=prose):
        self.assertEqual(audit(self.project(prose, 'import winreg'))['summary']['claims'], 0)
    add('excluded_prose_' + str(index), excluded_prose)


def inline(self):
    self.assertEqual(audit(self.project('works on `Windows`', 'import fcntl'))['status'], 'FAIL')
add('inline', inline)


def linux(self):
    self.assertEqual(audit(self.project('Linux-only', 'import fcntl'))['status'], 'PASS')
add('linux_only', linux)


def aliased(self):
    self.assertEqual(len(audit(self.project(code='import winreg as wr\nwr.OpenKey'))['findings']), 2)
add('aliased_import', aliased)

for index, test in enumerate(["sys.platform.startswith('linux')", "sys.platform.startswith('darwin')"]):
    def posix_prefix(self, test=test):
        self.assertEqual(audit(self.project(code='import sys\nif ' + test + ':\n    import fcntl'))['status'], 'PASS')
    add('posix_prefix_' + str(index), posix_prefix)


def optional_usage(self):
    code = 'try:\n    import fcntl as fc\nexcept ImportError:\n    fc = None\nif fc:\n    fc.flock(1, 2)'
    self.assertEqual(audit(self.project(code=code))['status'], 'PASS')
add('optional_module_usage', optional_usage)


def wrong_exception(self):
    self.assertEqual(len(audit(self.project(code='try:\n    import winreg\nexcept ValueError:\n    pass'))['findings']), 2)
add('wrong_exception', wrong_exception)

if __name__ == '__main__':
    unittest.main()
