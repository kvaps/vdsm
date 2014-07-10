# Copyright 2014 Red Hat, Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
#
# Refer to the README and COPYING files for full details of the license
#
from . import _parser
from . import _wrapper


def show(dev, parent=None, pref=None):
    command = ['filter', 'show', 'dev', dev]
    if parent is not None:
        command += ['parent', parent]
    if pref is not None:
        command += ['pref', pref]
    return _wrapper.process_request(command)


def parse(tokens):
    """Parses a filter entry token generator into a data dictionary"""
    data = {}
    for token in tokens:
        if token == 'root':
            data['root'] = True
        elif token == 'pref':
            data[token] = int(next(tokens))
        elif token in ('dev', 'parent', 'protocol'):
            data[token] = next(tokens)
        elif token in _CLASSES:
            data['kind'] = token
            break
    # At this point there should be a filter kind
    _filter_cls_parser = _CLASSES.get(data['kind'])
    if _filter_cls_parser is not None:
        data[data['kind']] = _filter_cls_parser(tokens)
    return data


def _parse_u32(tokens):
    """Returns a dictionary with the parsed information and consumes the parsed
    elements from the input list"""
    data = {}
    for token in tokens:
        if token in ('fh', 'link'):
            data[token] = next(tokens)
        elif token == 'order':
            data[token] = int(next(tokens))
        elif token in ('*flowid', 'flowid'):
            data['flowid'] = next(tokens)
        elif token == 'terminal':
            data['terminal'] = True
            _parser.consume(tokens, 'flowid')
            _parser.consume(tokens, '???')
        elif token == 'ht':
            _parser.consume(tokens, 'divisor')
            data['ht_divisor'] = int(next(tokens))
        elif token == 'key':
            _parser.consume(tokens, 'ht')
            data['key_ht'] = int(next(tokens), 16)
            _parser.consume(tokens, 'bkt')
            data['key_bkt'] = int(next(tokens), 16)
        elif token == '???':
            continue
        elif token == 0:  # line break
            continue
        elif token == 'match':
            match_first = next(tokens)
            if match_first.lower() == 'ip':
                data['match'] = _parse_match_ip(tokens)  # To implement
            else:
                data['match'] = _parse_match_raw(match_first, tokens)
        elif token == 'action':
            try:
                data['actions'].append(_parse_action(tokens))
            except KeyError:
                data['actions'] = [_parse_action(tokens)]
        else:
            break  # We should not get here unless iproute adds fields. Log?
    return data


_parse_match_ip = _parser.parse_skip_line  # Unimplemented, skip line


def _parse_match_raw(val_mask, tokens):
    """Parses tokens describing a raw match, e.g.,
    'match 001e0000/0fff0000 at -4' into a data dictionary"""
    value, mask = val_mask.split('/')
    value = int(value, 16)
    mask = int(mask, 16)
    _parser.consume(tokens, 'at')
    offset = int(next(tokens))
    return {'value': value, 'mask': mask, 'offset': offset}


def _parse_action(tokens):
    """Returns a dictionary with the parsed information and consumes the parsed
    elements from the input list"""
    data = {}
    for token in tokens:
        if token == 0:
            continue
        if token == 'order':
            data[token] = int(next(tokens)[:-1])  # without trailing ':'
            data['kind'] = next(tokens)
            action_opt_parse = _ACTIONS.get(data['kind'])
            if action_opt_parse is not None:
                data.update(action_opt_parse(tokens))
            return data
    raise _parser.TCParseError('Unexpected filter action format')


def _parse_mirred(tokens):
    """Parses the tokens of a mirred action into a data dictionary"""
    data = {}
    action = next(tokens)[1:]  # Get the first token without the opening paren
    if action == 'unkown':
        data['action'] = action
    else:
        data['action'] = '%s_%s' % (action.lower(), next(tokens).lower())
    _parser.consume(tokens, 'to')
    _parser.consume(tokens, 'device')
    data['target'] = next(tokens)[:-1]
    data['op'] = next(tokens)
    _parser.consume(tokens, _parser.LINE_DELIMITER)
    for token in tokens:
        if token in ('index', 'ref', 'bind'):
            data[token] = int(next(tokens))
        elif token == 0:
            break
        else:
            # We should not get here unless iproute adds fields. In any case,
            # we only need to report the fields that we care about. Safe to
            # stop parsing
            break
    return data


_ACTIONS = {'csum': None, 'gact': None, 'ipt': None, 'mirred': _parse_mirred,
            'nat': None, 'pedit': None, 'police': None, 'simple': None,
            'skbedit': None, 'xt': None}


_CLASSES = {'basic': None, 'cgroup': None, 'flow': None, 'fw': None,
            'route': None, 'rsvp': None, 'tcindex': None, 'u32': _parse_u32}