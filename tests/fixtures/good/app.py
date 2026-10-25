import sys
if sys.platform == 'win32':
    import winreg
try:
    import fcntl
except ImportError:
    fcntl = None
