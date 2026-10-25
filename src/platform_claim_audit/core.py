"""Static claims and evidence extraction; target code is never imported."""
import ast
import re
from pathlib import Path

PLATFORMS = {'windows', 'macos', 'linux'}
NAMES = {'windows': r'windows|win32|win', 'macos': r'macos|mac|osx|darwin', 'linux': r'linux'}
WINDOWS = {'winreg', 'msvcrt', '_winapi', 'winsound', 'nt', 'os.startfile', 'ctypes.windll', 'ctypes.WinDLL', 'ctypes.oledll'}
POSIX = {'fcntl', 'pwd', 'grp', 'termios', 'resource', 'syslog', 'os.fork', 'os.setsid', 'os.getuid', 'os.geteuid', 'os.getgid', 'os.uname'}
RULE = 'documented-platform-unsupported'


def claims(root):
    positive, negative = {}, set()
    paths = ([root / 'README.md'] if (root / 'README.md').is_file() else [])
    paths += sorted((root / 'docs').rglob('*.md')) if (root / 'docs').is_dir() else []
    for path in paths:
        fence = None
        for number, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
            marker = re.match(r'^\s{0,3}(`{3,}|~{3,})', line)
            if marker:
                token = marker.group(1)
                if fence is None:
                    fence = token
                elif token[0] == fence[0] and len(token) >= len(fence):
                    fence = None
                continue
            if fence:
                continue
            low = line.lower()
            removed = set()
            for platform, names in NAMES.items():
                name = r'\b(?:' + names + r')\b'
                if any(re.search(pattern, low) for pattern in (
                    r'not supported on\s+' + name, r'no\s+' + name + r'\s+support',
                    name + r'\s+not supported', r'does not support\s+' + name)):
                    removed.add(platform)
            if removed:
                negative.update(removed)
                continue
            for platform, names in NAMES.items():
                name = r'\b(?:' + names + r')\b'
                if (re.search(r'cross[- ]platform', low) or
                    (re.search(r'\b(works on|runs on|supports|support for|supported on)\b', low) and re.search(name, low)) or
                    re.search(name + r'(?:\s+support\b|[- ]only\b|\s+required\b)', low) or
                    re.search(r'\brequires\s+' + name, low)):
                    positive.setdefault(platform, (path.relative_to(root).as_posix(), number))
    return {p: location for p, location in positive.items() if p not in negative}


def source_paths(root):
    for path in sorted(root.rglob('*.py')):
        relative = path.relative_to(root)
        if (any(part in {'tests', 'fixtures', 'docs', '.git', '.venv', 'venv', '__pycache__', 'build', 'dist'} for part in relative.parts[:-1])
                or path.name.startswith('test_') or path.name.endswith('_test.py') or path.is_symlink()):
            continue
        yield path


class Evidence(ast.NodeVisitor):
    def __init__(self):
        self.aliases = {}
        self.guard = None
        self.fallback = False
        self.items = []

    def chain(self, node):
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            base = self.chain(node.value)
            return base + '.' + node.attr if base else ''
        return ''

    def record(self, api, node):
        if api in WINDOWS | POSIX and not self.fallback:
            self.items.append((api, node.lineno, self.guard))

    def visit_Import(self, node):
        for entry in node.names:
            self.aliases[entry.asname or entry.name.split('.')[0]] = entry.name if entry.asname else entry.name.split('.')[0]
            self.record(entry.name, node)

    def visit_ImportFrom(self, node):
        if node.level:
            return
        self.record(node.module, node)
        for entry in node.names:
            full = (node.module or '') + '.' + entry.name
            self.aliases[entry.asname or entry.name] = full
            self.record(full, node)

    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Load) and '.' in self.chain(node):
            self.record(self.chain(node), node)

    def visit_Attribute(self, node):
        self.record(self.chain(node), node)
        self.generic_visit(node)

    def resolve(self, test):
        literal, target = None, ''
        if isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], ast.Eq):
            left, right = test.left, test.comparators[0]
            if isinstance(left, ast.Constant):
                left, right = right, left
            target = self.chain(left)
            if isinstance(right, ast.Constant):
                literal = right.value
        elif isinstance(test, ast.Call) and isinstance(test.func, ast.Attribute) and test.func.attr == 'startswith' and len(test.args) == 1 and not test.keywords:
            target = self.chain(test.func.value)
            if isinstance(test.args[0], ast.Constant):
                literal = test.args[0].value
        if target == 'sys.platform':
            return {'win': {'windows'}, 'win32': {'windows'}, 'cygwin': {'windows'}, 'darwin': {'macos'}, 'linux': {'linux'}}.get(literal) if isinstance(literal, str) else None
        if target == 'os.name':
            return {'nt': {'windows'}, 'posix': {'macos', 'linux'}}.get(literal) if isinstance(literal, str) else None
        return None

    def branch(self, nodes, guard):
        old = self.guard
        self.guard = guard
        for node in nodes:
            self.visit(node)
        self.guard = old

    def visit_If(self, node):
        self.visit(node.test)
        resolved = self.resolve(node.test)
        self.branch(node.body, (resolved & self.guard if self.guard is not None else resolved) if resolved is not None else self.guard)
        complement = PLATFORMS - resolved if resolved is not None else self.guard
        self.branch(node.orelse, complement & self.guard if complement is not None and self.guard is not None else complement)

    def visit_Try(self, node):
        catches = any(h.type is None or isinstance(h.type, ast.Name) and h.type.id == 'ImportError' or isinstance(h.type, ast.Tuple) and any(isinstance(n, ast.Name) and n.id == 'ImportError' for n in h.type.elts) for h in node.handlers)
        old = self.fallback
        self.fallback = old or catches
        for child in node.body:
            self.visit(child)
        self.fallback = old
        for child in node.handlers + node.orelse + node.finalbody:
            self.visit(child)


def audit(directory, ignore=()):
    root = Path(directory)
    if not root.is_dir():
        raise ValueError('target must be a project directory')
    documented = claims(root)
    sources = list(source_paths(root))
    found = {}
    for path in sources:
        try:
            tree = ast.parse(path.read_text(encoding='utf-8'))
        except (SyntaxError, UnicodeError):
            continue
        visitor = Evidence()
        visitor.visit(tree)
        for api, line, guard in sorted(visitor.items, key=lambda item: (item[1], item[0])):
            unavailable = {'macos', 'linux'} if api in WINDOWS else {'windows'}
            for platform in sorted(documented.keys() & unavailable):
                if guard is None or platform in guard:
                    found.setdefault((platform, api), (path.relative_to(root).as_posix(), line))
    if not sources:
        for platform in documented:
            found[(platform, '<no-source>')] = ('<no-source>', 0)
    findings = []
    if RULE not in ignore:
        for (platform, api), (code_file, code_line) in found.items():
            docs_file, docs_line = documented[platform]
            findings.append(dict(rule=RULE, severity='HIGH', docs_file=docs_file, docs_line=docs_line, claim=platform, code_file=code_file, code_line=code_line, api=api))
    findings.sort(key=lambda f: (f['rule'], f['claim'], f['code_file'], f['code_line'], f['api']))
    verified = sorted(set(documented) - {p for p, api in found})
    return dict(status='FAIL' if findings else 'PASS', findings=findings, verified_claims=verified,
                summary=dict(claims=len(documented), source_files=len(sources), findings=len(findings)))
