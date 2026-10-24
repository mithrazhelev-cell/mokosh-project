"""One bounded EWMH activation request for two supplied own Tk windows.

Executed in a private subprocess, never imported into the Tk event loop.
No geometry/property writes, withdrawal, direct input focus, desktop switching,
global grab, extra thread, retry loop or window-title search is performed.
"""
from __future__ import annotations

import argparse
import ctypes as C
import json
import os
import re
import subprocess


class Declined(Exception):
    pass


def require(condition, reason):
    if not condition:
        raise Declined(reason)


def query(*arguments):
    result = subprocess.run(arguments, stdin=subprocess.DEVNULL, capture_output=True,
                            text=True, timeout=0.25, check=False)
    require(result.returncode == 0 and len(result.stdout) <= 65536, 'QUERY_FAILED_OR_OVERSIZED')
    return result.stdout


def tree(text):
    root = re.search(r'Root window id:\s*(0x[0-9a-fA-F]+)', text)
    parent = re.search(r'Parent window id:\s*(0x[0-9a-fA-F]+)', text)
    require(root is not None and parent is not None, 'OWN_TREE_NOT_PARSED')
    return int(root[1], 16), int(parent[1], 16)


def wm_state(text):
    match = re.search(r'window state:\s*(Normal|Iconic|Withdrawn)\b', text)
    require(match is not None, 'WM_STATE_MISSING')
    return match[1]


def flags(text):
    match = re.search(r'^_NET_WM_STATE\(ATOM\)\s*=([^\n]*)$', text, re.M)
    require(match is not None, 'NET_STATE_MISSING')
    return frozenset(x.strip() for x in match[1].split(',') if x.strip())


def cardinal(text, name):
    match = re.search(r'^' + re.escape(name) + r'\(CARDINAL\)\s*=\s*([0-9]+)\s*$', text, re.M)
    require(match is not None, 'DESKTOP_PROPERTY_MISSING')
    value = int(match[1]); require(0 <= value < 2**32, 'CARDINAL_OUT_OF_RANGE')
    return value


def window_property(text, name):
    match = re.search(r'^' + re.escape(name) + r'\(WINDOW\): window id #\s*(0x[0-9a-fA-F]+)\s*$', text, re.M)
    require(match is not None, 'ACTIVE_WINDOW_PROPERTY_MISSING')
    return int(match[1], 16)


def activation_plan(snapshot, timestamp):
    require(type(timestamp) is int and 0 < timestamp < 2**32, 'NO_REAL_USER_TIMESTAMP')
    root, parent, child = snapshot['root'], snapshot['parent_wrapper'], snapshot['child_wrapper']
    require(all(type(v) is int and 0 < v < 2**32 for v in (root, parent, child))
            and len({root, parent, child}) == 3, 'INVALID_WRAPPER_IDS')
    require(snapshot['parent_state'] == 'Iconic' and snapshot['child_state'] == 'Normal', 'WRONG_NATIVE_STATE')
    wanted = {'_NET_WM_STATE_HIDDEN', '_NET_WM_STATE_MAXIMIZED_HORZ', '_NET_WM_STATE_MAXIMIZED_VERT'}
    require(wanted <= snapshot['parent_flags'] and '_NET_WM_STATE_FULLSCREEN' not in snapshot['parent_flags'],
            'OUTSIDE_CONFIRMED_MAXIMIZED_MISMATCH')
    require('_NET_WM_STATE_HIDDEN' not in snapshot['child_flags'] and snapshot['active'] == child,
            'CHILD_NOT_NATIVE_ACTIVE')
    require(snapshot['desktop'] == snapshot['parent_desktop'] == snapshot['child_desktop']
            and snapshot['desktop'] != 0xffffffff, 'DESKTOP_MISMATCH')
    require(snapshot['supported'] is True and {parent, child} <= snapshot['managed'], 'UNMANAGED_OR_UNSUPPORTED')
    return {'root':root, 'window':parent, 'message_type':'_NET_ACTIVE_WINDOW', 'format':32,
            'source_indication':1, 'timestamp':timestamp, 'requestor_active_window':child,
            'data':[1,timestamp,child,0,0], 'propagate':False, 'event_mask':(1 << 19) | (1 << 20)}


def observe(parent_inner, child_inner, read=query):
    root, parent = tree(read('xwininfo','-id',hex(parent_inner),'-tree','-stats'))
    child_root, child = tree(read('xwininfo','-id',hex(child_inner),'-tree','-stats'))
    require(root == child_root and parent not in (root,parent_inner,child_inner)
            and child not in (root,parent_inner,child_inner) and parent != child, 'OWN_WRAPPER_CHAIN_DIFFERS')
    properties = ('WM_STATE','_NET_WM_STATE','_NET_WM_DESKTOP')
    p = read('xprop','-id',hex(parent),*properties)
    c = read('xprop','-id',hex(child),*properties)
    r = read('xprop','-id',hex(root),'_NET_ACTIVE_WINDOW','_NET_CURRENT_DESKTOP',
             '_NET_SUPPORTED','_NET_CLIENT_LIST')
    clients = re.search(r'^_NET_CLIENT_LIST\(WINDOW\): window id #\s*([^\n]*)$', r, re.M)
    supported = re.search(r'^_NET_SUPPORTED\(ATOM\)\s*=([^\n]*)$', r, re.M)
    require(clients is not None and supported is not None, 'ROOT_SUPPORT_OR_CLIENTS_MISSING')
    return {'root':root, 'parent_wrapper':parent, 'child_wrapper':child,
            'parent_state':wm_state(p), 'child_state':wm_state(c),
            'parent_flags':flags(p), 'child_flags':flags(c),
            'active':window_property(r,'_NET_ACTIVE_WINDOW'),
            'desktop':cardinal(r,'_NET_CURRENT_DESKTOP'),
            'parent_desktop':cardinal(p,'_NET_WM_DESKTOP'), 'child_desktop':cardinal(c,'_NET_WM_DESKTOP'),
            'managed':set(int(x,16) for x in re.findall(r'0x[0-9a-fA-F]+',clients[1])),
            'supported':'_NET_ACTIVE_WINDOW' in {s.strip() for s in supported[1].split(',')}}


class ClientData(C.Union):
    _fields_ = [('b',C.c_char*20),('s',C.c_short*10),('l',C.c_long*5)]


class ClientMessage(C.Structure):
    _fields_ = [('type',C.c_int),('serial',C.c_ulong),('send_event',C.c_int),
                ('display',C.c_void_p),('window',C.c_ulong),('message_type',C.c_ulong),
                ('format',C.c_int),('data',ClientData)]


class XEvent(C.Union):
    _fields_ = [('xclient',ClientMessage),('pad',C.c_long*24)]


def make_event(plan, display, atom):
    require(plan['format']==32 and plan['source_indication']==1 and plan['propagate'] is False
            and plan['event_mask']==(1 << 19) | (1 << 20)
            and plan['data']==[1,plan['timestamp'],plan['requestor_active_window'],0,0], 'INVALID_MESSAGE_PLAN')
    event = XEvent()
    event.xclient.type=33  # X11 ClientMessage, as defined by the X11 protocol.
    event.xclient.display=display
    event.xclient.window=plan['window']
    event.xclient.message_type=atom
    event.xclient.format=32
    for i,value in enumerate(plan['data']):event.xclient.data.l[i]=value
    return event


def send(plan, library=None):
    lib=library if library is not None else C.CDLL('libX11.so.6')
    for name, restype, argtypes in (
        ('XOpenDisplay',C.c_void_p,[C.c_char_p]),
        ('XDefaultRootWindow',C.c_ulong,[C.c_void_p]),
        ('XInternAtom',C.c_ulong,[C.c_void_p,C.c_char_p,C.c_int]),
        ('XSendEvent',C.c_int,[C.c_void_p,C.c_ulong,C.c_int,C.c_long,C.POINTER(XEvent)]),
        ('XFlush',C.c_int,[C.c_void_p]),('XCloseDisplay',C.c_int,[C.c_void_p])):
        fn=getattr(lib,name);fn.restype=restype;fn.argtypes=argtypes
    display=lib.XOpenDisplay(None)
    require(bool(display),'DISPLAY_UNAVAILABLE')
    try:
        require(int(lib.XDefaultRootWindow(display))==plan['root'],'DISPLAY_ROOT_CHANGED')
        atom=int(lib.XInternAtom(display,b'_NET_ACTIVE_WINDOW',1))
        require(atom!=0,'ACTIVATION_ATOM_MISSING')
        event=make_event(plan,display,atom)
        require(lib.XSendEvent(display,plan['root'],0,plan['event_mask'],C.byref(event))!=0,'SEND_EVENT_REJECTED')
        lib.XFlush(display)
    finally:
        lib.XCloseDisplay(display)
    return {'status':'REQUEST_SENT_NOT_ACCEPTANCE','parent_wrapper':hex(plan['window']),
            'source_indication':1,'timestamp':plan['timestamp'],
            'window_manager_may_refuse':True,'control_focus_changed_by_this_helper':False}


def execute(parent,child,timestamp,owner_pid,read=query,sender=send):
    require(type(owner_pid) is int and owner_pid==os.getppid(), 'NOT_GUI_CHILD_PROCESS')
    require(all(type(v) is int and 0<v<2**32 for v in (parent,child)) and parent!=child,'INVALID_INNER_IDS')
    snapshot=observe(parent,child,read)
    plan=activation_plan(snapshot,timestamp)
    # Recheck the active child after gathering the other native properties.
    current=read('xprop','-id',hex(plan['root']),'_NET_ACTIVE_WINDOW')
    require(window_property(current,'_NET_ACTIVE_WINDOW')==plan['requestor_active_window'],'ACTIVE_CHILD_CHANGED')
    return sender(plan)


def main():
    parser=argparse.ArgumentParser(allow_abbrev=False)
    for name in ('parent','child','timestamp','owner-pid'):parser.add_argument('--'+name,type=int,required=True)
    args=parser.parse_args()
    try:
        result=execute(args.parent,args.child,args.timestamp,args.owner_pid)
    except Declined as error:
        result={'status':'DECLINED','reason':str(error)}
    except Exception as error:
        result={'status':'UNAVAILABLE','error_type':type(error).__name__}
    print(json.dumps(result,sort_keys=True))


if __name__=='__main__':main()
