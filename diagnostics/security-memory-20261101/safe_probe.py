"""Windows-only SYNTHETIC state protocol; not a MOKOSH backend or secret vault.

Never retain live fixture data in an unlocked/NOACCESS page. Destroy the page
contents before explicit unlock; re-lock an empty page before reloading PUBLIC
fixture bytes. No real key reload/recovery or kernel protection is implemented.
"""
import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('cause_probe', ROOT/'probe.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
MODES = ('locked_ro_cycle','park_reload','parked_noaccess_read','live_noaccess_refused','control_read_write','timeout')


class ProtocolError(RuntimeError): pass


class SyntheticPage(base.Page):
    def __init__(self, case):
        if sys.platform != 'win32':
            raise ProtocolError('Windows only; no permissive fallback')
        self.state = 'INITIALIZING'
        try:
            super().__init__(case=case)
            self.require_locked('initial_live_guard')
            self.state = 'LIVE'
        except BaseException:
            if getattr(self,'address',None) is not None:
                base.Page.close(self)
            self.state = 'CLOSED'
            raise

    def require_locked(self, phase):
        s = self.snapshot(phase)
        if not s or s['valid'] is not True or s['locked'] is not True:
            raise ProtocolError('live-page lock not observed: '+phase)

    def protect(self, mode):
        if mode == 'none' and self.state not in ('EMPTY','PARKED'):
            raise ProtocolError('NOACCESS requires a verified empty, explicitly unlocked page')
        base.Page.protect(self,mode)
        if self.state == 'LIVE':
            self.require_locked('live_after_protect:'+mode)

    def park_empty(self):
        if self.state != 'LIVE': raise ProtocolError('park requires LIVE')
        self.require_locked('before_park')
        self.state='WIPING'
        base.Page.protect(self,'rw')
        ctypes.memset(self.address,0,self.size)
        if ctypes.string_at(self.address,self.size) != bytes(self.size):
            raise ProtocolError('park full-page zero verification failed')
        base.emit('PARK_WIPED',mode=self.case,bytes=self.size,verified=True)
        self._win_call('VirtualUnlock',self.address,self.size,phase='park_unlock_empty')
        self.locked=False
        self.state='EMPTY'
        self.protect('none')
        self.state='PARKED'
        base.emit('PARKED_EMPTY',mode=self.case,live_data_present=False)

    def reload_public_fixture(self):
        if self.state != 'PARKED': raise ProtocolError('reload requires PARKED')
        self.state='EMPTY'
        base.Page.protect(self,'rw')
        self._win_call('VirtualLock',self.address,self.size,phase='reload_lock_empty')
        self.locked=True
        self.require_locked('before_public_reload')
        if ctypes.string_at(self.address,self.size) != bytes(self.size):
            raise ProtocolError('parked page is no longer empty')
        ctypes.memmove(self.address,base.VALUE,len(base.VALUE))
        if ctypes.string_at(self.address,len(base.VALUE)) != base.VALUE:
            raise ProtocolError('public fixture reload mismatch')
        self.state='LIVE'
        base.emit('PUBLIC_FIXTURE_RELOADED',mode=self.case,locked_before_load=True)

    def close(self):
        if self.state == 'CLOSED': return
        self.state='CLOSING'
        try: base.Page.close(self)
        finally: self.state='CLOSED'


def child(mode):
    base.configure_child()
    if mode=='timeout':
        base.emit('READY',mode=mode)
        while True: time.sleep(1)
    p=SyntheticPage(mode)
    try:
        if mode=='locked_ro_cycle':
            p.protect('ro')
            if ctypes.string_at(p.address,len(base.VALUE))!=base.VALUE: raise ProtocolError('RO read')
            p.protect('rw')
        elif mode=='park_reload':
            p.park_empty();p.reload_public_fixture()
        elif mode=='parked_noaccess_read':
            p.park_empty();base.emit('READY',mode=mode,empty_before_noaccess=True)
            try: ctypes.string_at(p.address,1)
            except OSError as exc:
                if 'access violation' not in str(exc).lower(): raise
                base.emit('ACCESS_VIOLATION',mode=mode,origin='ctypes_SEH')
                return 31
            base.emit('ACCESS_SUCCEEDED',mode=mode)
            return 2
        elif mode=='live_noaccess_refused':
            try:p.protect('none')
            except ProtocolError:base.emit('LIVE_NOACCESS_REFUSED',mode=mode)
            else:raise ProtocolError('live page was allowed into NOACCESS')
        elif mode=='control_read_write':
            ctypes.memset(p.address,90,1)
            if ctypes.string_at(p.address,1)!=b'Z':raise ProtocolError('positive write/read control')
            base.emit('CONTROL_READBACK',mode=mode,verified=True,bytes=1)
        else:raise ProtocolError('unexpected mode')
        base.emit('CASE_ACTION_COMPLETED',mode=mode)
        return 0
    finally:p.close()


def run_child(mode):
    start=time.monotonic()
    env={k:os.environ[k] for k in ('SystemRoot','WINDIR','TEMP','TMP','PATH','LANG') if k in os.environ}
    p=subprocess.Popen([sys.executable,'-I','-B',str(Path(__file__).resolve()),'--child',mode],
        stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,close_fds=True)
    timed_out=False
    try:
        try:out,err=p.communicate(timeout=5 if mode=='timeout' else 30)
        except subprocess.TimeoutExpired:
            timed_out=True;p.kill();out,err=p.communicate(timeout=5)
    finally:
        if p.poll() is None:p.kill();p.wait(timeout=5)
    if len(out)>65536 or len(err)>8192:raise ProtocolError('bounded output exceeded')
    return dict(mode=mode,exit=p.returncode,timed_out=timed_out,reaped=p.poll() is not None,
        elapsed_seconds=round(time.monotonic()-start,3),events=[json.loads(l) for l in out.decode().splitlines()],stderr=err.decode('utf-8','replace'))


def assess(rows):
    if len(rows)!=6 or {r['mode'] for r in rows}!=set(MODES):raise ProtocolError('case inventory')
    checks={}
    for r in rows:
        mode=r['mode'];ev=r['events']
        ok=r['reaped'] is True and not r['stderr'] and type(r['exit']) is int
        if mode=='timeout':
            ok=ok and r['timed_out'] is True and r['exit']!=0 and ev==[dict(event='READY',mode=mode)]
        else:
            ok=ok and r['timed_out'] is False and all(e.get('mode')==mode for e in ev)
            calls=[e for e in ev if e.get('event')=='API_CALL']
            ok=ok and bool(calls) and all(e.get('succeeded') is True and type(e.get('win32_error')) is int and e['win32_error']==0 for e in calls)
            ok=ok and calls[-1].get('operation')=='VirtualFree'
            ok=ok and any(e.get('event')=='PAGE_STATE' and e.get('phase')=='initial_live_guard' and e.get('valid') is True and e.get('locked') is True for e in ev)
            ok=ok and any(e.get('event')=='MEMORY_ZEROED' and e.get('bytes')==4096 and e.get('readback_bytes')==4096 for e in ev)
            def index(event,**fields):
                return next((i for i,e in enumerate(ev) if e.get('event')==event and all(e.get(k)==v for k,v in fields.items())),-1)
            if mode in ('park_reload','parked_noaccess_read'):
                wipe=index('PARK_WIPED',bytes=4096,verified=True)
                unlock=index('API_CALL',operation='VirtualUnlock',phase='park_unlock_empty')
                none=index('API_CALL',operation='VirtualProtect',phase='protect:none')
                parked=index('PARKED_EMPTY',live_data_present=False)
                ok=ok and 0<=wipe<unlock<none<parked
                if mode=='park_reload':
                    lock=index('API_CALL',operation='VirtualLock',phase='reload_lock_empty')
                    guard=index('PAGE_STATE',phase='before_public_reload',valid=True,locked=True)
                    loaded=index('PUBLIC_FIXTURE_RELOADED',locked_before_load=True)
                    ok=ok and parked<lock<guard<loaded
                else:
                    ready=index('READY',empty_before_noaccess=True)
                    av=index('ACCESS_VIOLATION',origin='ctypes_SEH')
                    ok=ok and parked<ready<av and r['exit']==31 and index('ACCESS_SUCCEEDED')<0
                    ok=ok and sum(e.get('operation')=='VirtualUnlock' for e in calls)==1
            if mode=='live_noaccess_refused':
                ok=ok and index('LIVE_NOACCESS_REFUSED')>=0 and index('API_CALL',operation='VirtualProtect',phase='protect:none')<0
            if mode=='locked_ro_cycle':
                ro=index('PAGE_STATE',phase='live_after_protect:ro',valid=True,locked=True,protection=2)
                rw=index('PAGE_STATE',phase='live_after_protect:rw',valid=True,locked=True,protection=4)
                ok=ok and 0<=ro<rw and index('API_CALL',operation='VirtualProtect',phase='protect:none')<0
            if mode=='control_read_write':ok=ok and index('CONTROL_READBACK',verified=True,bytes=1)>=0
            if mode!='parked_noaccess_read':ok=ok and r['exit']==0 and index('CASE_ACTION_COMPLETED')>=0
        checks[mode]=bool(ok)
    return checks


def run(destination):
    d=Path(destination);d.mkdir(parents=True,exist_ok=False)
    report=dict(schema=1,scope='SYNTHETIC_WINDOWS_EMPTY_PARK_PROTOCOL_ONLY',status='STOP',product_accepted=False,
        product_backend_implemented=False,product_executed=False,physical_GUI_tested=False,
        all_secret_copies_protected=False,continuous_lock_during_empty_NOACCESS=False,
        source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    try:
        if sys.platform!='win32' or platform.machine().lower() not in ('amd64','x86_64'):raise ProtocolError('Windows/x64 only')
        report['environment']=dict(system=platform.system(),machine=platform.machine(),python=platform.python_version(),page_size=base.mmap.PAGESIZE,privilege=base.privilege())
        report['ci']={k:os.environ.get(k) for k in ('GITHUB_SHA','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','ImageOS','ImageVersion')}
        report['results']=[run_child(m) for m in MODES];report['checks']=assess(report['results'])
        report['status']='SCOPED_EMPTY_PARK_PROTOCOL_PASS_PRODUCT_NOT_ACCEPTED' if all(report['checks'].values()) else 'FAIL'
    except Exception as exc:report['error']=dict(type=type(exc).__name__,message=str(exc)[:500])
    (d/'RESULT.json').write_text(json.dumps(report,indent=2)+'\n')
    return 0 if report['status']=='SCOPED_EMPTY_PARK_PROTOCOL_PASS_PRODUCT_NOT_ACCEPTED' else 1


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);g=p.add_mutually_exclusive_group(required=True)
    g.add_argument('--child',choices=MODES);g.add_argument('--output');a=p.parse_args();os.umask(0o077)
    raise SystemExit(child(a.child) if a.child else run(a.output))
