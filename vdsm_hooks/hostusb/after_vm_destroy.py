#!/usr/bin/python

import os
import re
import sys
import traceback

import hooking

'''
after_vm_destroy:
return the original owner of the usb device
'''

HOOK_HOSTUSB_PATH = '/var/run/vdsm/hooks/hostusb-permissions'


def get_owner(devpath):
    uid = pid = -1
    content = ''

    if not os.path.isfile(HOOK_HOSTUSB_PATH):
        return uid, pid

    with open(HOOK_HOSTUSB_PATH, 'r') as f:
        for line in f:
            if len(line) > 0 and line.split(':')[0] == devpath:
                entry = line.split(':')
                uid = entry[1]
                pid = entry[2]
            elif len(line) > 0:
                content += line + '\n'

    if uid != -1:
        with open(HOOK_HOSTUSB_PATH, 'w') as f:
            f.writelines(content)

    return uid, pid


# !TODO:
# merge chown with before_vm_start.py
# maybe put it in hooks.py?
def chown(busid, deviceid):

    devid = busid + ':' + deviceid
    command = ['lsusb', '-s', devid]
    retcode, out, err = hooking.execCmd(command, raw=True)
    if retcode != 0:
        sys.stderr.write('hostusb: cannot find usb device: %s\n' % devid)
        sys.exit(2)

    devpath = '/dev/bus/usb/' + out[4:7] + '/' + out[15:18]

    uid, gid = get_owner(devpath)
    if uid == -1:
        sys.stderr.write('hostusb after_vm_destroy: cannot find devpath: %s '
                         'in file: %s\n' % (devpath, HOOK_HOSTUSB_PATH))
        return

    # we don't use os.chown because we need sudo
    owner = str(uid) + ':' + str(gid)
    command = ['/bin/chown', owner, devpath]
    retcode, out, err = hooking.execCmd(command, sudo=True, raw=True)
    if retcode != 0:
        sys.stderr.write('hostusb after_vm_destroy: error chown %s to %s, '
                         'err = %s\n' % (devpath, owner, err))
        sys.exit(2)

if 'hostusb' in os.environ:
    try:
        regex = re.compile('^0x[\d,A-F,a-f]{4}$')
        for usb in os.environ['hostusb'].split('&'):
            busid, deviceid = usb.split(':')
            if len(regex.findall(busid)) != 1 or \
                    len(regex.findall(deviceid)) != 1:
                sys.stderr.write('hostusb after_vm_destroy: bad input, '
                                 'expected format for bus and '
                                 'device, input: %s:%s\n' %
                                 (busid, deviceid))
                sys.exit(2)
            chown(busid, deviceid)

    except:
        sys.stderr.write('hostusb after_vm_destroy: [unexpected error]: %s\n' %
                         traceback.format_exc())
        sys.exit(2)
