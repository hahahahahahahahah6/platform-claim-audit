"""Command line interface."""
import argparse
import json
import sys
from . import __version__
from .core import audit


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(1, 'error: ' + message + '\n')


def main(argv=None):
    parser = Parser(description='Audit documented platform promises against Python source.')
    parser.add_argument('directory', nargs='?', default='.')
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--fail-on', choices=['HIGH', 'MEDIUM'], default='MEDIUM')
    parser.add_argument('--ignore', default='')
    parser.add_argument('--verbose', action='store_true')
    parser.add_argument('--version', action='version', version=__version__)
    args = parser.parse_args(argv)
    try:
        result = audit(args.directory, {s.strip() for s in args.ignore.split(',')})
    except (OSError, UnicodeError, ValueError) as error:
        print('error: ' + str(error), file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        for f in result['findings']:
            print('{severity} {rule} {docs_file}:{docs_line} {claim} {code_file}:{code_line} {api}'.format(**f))
        if args.verbose:
            for platform in result['verified_claims']:
                print('OK platform ' + platform)
    return 2 if result['status'] == 'FAIL' else 0


if __name__ == '__main__':
    sys.exit(main())
