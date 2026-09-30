#!/usr/bin/env python3

"""
Look up a .github/trains.json entry by branch or train.

resolve-train.py branch BRANCH
resolve-train.py train TRAIN

Prints the matching entry as one line of JSON.  TRAINS_JSON overrides
the config path.  Every lookup validates the whole file.

Exit status:
  0  entry printed
  3  config valid, no match
  1  config missing or invalid (reason on stderr)
"""

import json
import os
import re
import sys
from collections import Counter

# Field names in .github/trains.json.
TRAINS = 'trains'
TRAIN = 'train'
BRANCH = 'branch'

# train ends up in a gh command-line argument: no shell metacharacters,
# no leading '-'.
FIELDS = {
    TRAIN: r'[A-Za-z0-9][A-Za-z0-9._-]*',
    BRANCH: r'[A-Za-z0-9][A-Za-z0-9._/-]*',
}

# Lookup keys; each value must be unique.
LOOKUPS = (BRANCH, TRAIN)

NO_MATCH = 3


def die(*message):
    print('ERROR:', *message, file=sys.stderr)
    sys.exit(1)


def usage():
    print(f'usage: resolve-train.py {BRANCH} BRANCH | {TRAIN} TRAIN',
          file=sys.stderr)
    sys.exit(1)


def load(config):
    """Read and validate the config."""
    try:
        with open(config) as f:
            doc = json.load(f)
    except FileNotFoundError:
        die(f'{config} is missing on this branch')
    except json.JSONDecodeError as error:
        die(f'{config} is not valid JSON: {error}')
    except OSError as error:
        die(f'{config} is unreadable: {error.strerror}')

    # An empty list is valid: nothing publishes.
    trains = doc.get(TRAINS) if isinstance(doc, dict) else None
    if not isinstance(trains, list):
        die(f'{config} has no {TRAINS}[] list')

    malformed = []
    for index, entry in enumerate(trains):
        if not isinstance(entry, dict):
            malformed.append(f'{TRAINS}[{index}] is not an object')
            continue
        for field, pattern in FIELDS.items():
            value = entry.get(field)
            if not isinstance(value, str) or not re.fullmatch(pattern, value):
                malformed.append(
                    f'{TRAINS}[{index}] {field}={json.dumps(value)}')
    if malformed:
        die(f'{config} has entries with a missing or malformed',
            f'{"/".join(FIELDS)}:', '; '.join(malformed))

    duplicated = [f'{field} {value}'
                  for field in LOOKUPS
                  for value, count in Counter(e[field] for e in trains).items()
                  if count > 1]
    if duplicated:
        die(f'{config} lists {", ".join(duplicated)} more than once;',
            'two builds would fight over one release')

    return doc


def main(argv):
    if len(argv) != 2 or argv[0] not in LOOKUPS:
        usage()
    field, key = argv

    doc = load(os.environ.get('TRAINS_JSON') or '.github/trains.json')

    for entry in doc[TRAINS]:
        if entry[field] == key:
            print(json.dumps(entry, separators=(',', ':')))
            return 0
    return NO_MATCH


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
