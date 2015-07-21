#!/usr/bin/python

import re
import os
import sys
import grp
import pwd
import traceback

import hooking

'''
host usb hook
=============

          !!! Disclaimer !!!
*******************************************
The host side usb support wasn't thoroughly
tests in kvm!
*******************************************

add hosts usb device/s to VM:

<hostdev mode='subsystem' type='usb'>
    <source>
        <address bus='1' device='3' />
    </source>
</hostdev>

syntax:
    hostusb=1-3&2-1
    i.e.
    hostusb=Bus-Device (can add more then one with '&' separator)

Note:
    The VM must be pinned to host and this hook will
    fail any migration attempt.
'''

HOOK_HOSTUSB_PATH = '/var/run/vdsm/hooks/hostusb-permissions'


def log_dev_owner(devpath, user, group):
    entry = devpath + ":" + str(user) + ":" + str(group)

    if not os.path.isdir(os.path.dirname(HOOK_HOSTUSB_PATH)):
        os.mkdir(os.path.dirname(HOOK_HOSTUSB_PATH))

    if os.path.isfile(HOOK_HOSTUSB_PATH):
        with open(HOOK_HOSTUSB_PATH, 'r') as f:
            for line in f:
                if entry == line:
                    return

    with open(HOOK_HOSTUSB_PATH, 'a') as f:
        f.writelines(entry)


# !TODO:
# merge chown with after_vm_destroy.py
# maybe put it in hooks.py?
def chown(busid, deviceid):

    devid = busid + ':' + deviceid
    command = ['lsusb', '-s', devid]
    retcode, out, err = hooking.execCmd(command, raw=True)
    if retcode != 0:
        sys.stderr.write('hostusb: cannot find usb device: %s\n' % devid)
        sys.exit(2)

    # find the device path:
    # /dev/bus/usb/xxx/xxx
    devpath = '/dev/bus/usb/' + out[4:7] + '/' + out[15:18]
    stat = os.stat(devpath)

    group = grp.getgrnam('qemu')
    gid = group.gr_gid
    user = pwd.getpwnam('qemu')
    uid = user.pw_uid

    # we don't use os.chown because we need sudo
    owner = str(uid) + ':' + str(gid)
    command = ['/bin/chown', owner, devpath]
    retcode, out, err = hooking.execCmd(command, sudo=True, raw=True)
    if retcode != 0:
        sys.stderr.write('hostusb: error chown %s to %s, err = %s\n' %
                         (devpath, owner, err))
        sys.exit(2)

    log_dev_owner(devpath, stat.st_uid, stat.st_gid)


def create_usb_device(domxml, busid, deviceid):
    hostdev = domxml.createElement('hostdev')
    hostdev.setAttribute('mode', 'subsystem')
    hostdev.setAttribute('type', 'usb')

    source = domxml.createElement('source')
    hostdev.appendChild(source)

    address = domxml.createElement('address')
    address.setAttribute('bus', busid)
    address.setAttribute('device', deviceid)
    source.appendChild(address)

    return hostdev

if 'hostusb' in os.environ:
    try:
        regex = re.compile('^[0-9]*$')
        domxml = hooking.read_domxml()
        devices = domxml.getElementsByTagName('devices')[0]

        for usb in os.environ['hostusb'].split('&'):
            busid, deviceid = usb.split(':')
            if len(regex.findall(busid)) != 1 or \
                    len(regex.findall(deviceid)) != 1:
                sys.stderr.write('hostusb: bad input, expected format '
                                 'for bus and device, input: %s:%s\n' %
                                 (busid, deviceid))
                sys.exit(2)

            hostdev = create_usb_device(domxml, busid, deviceid)
            devices.appendChild(hostdev)
            chown(busid, deviceid)

        hooking.write_domxml(domxml)
    except:
        sys.stderr.write('hostusb: [unexpected error]: %s\n' %
                         traceback.format_exc())
        sys.exit(2)
