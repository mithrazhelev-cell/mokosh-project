"""Only public fixtures; isolated Windows session-memory API qualification."""
import argparse,ctypes,hashlib,json,os,platform,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parent;sys.path.insert(0,str(ROOT))
import probe
from session_key import RetainedSessionKey,WindowsMemoryBackend
KEY=bytes(range(32)) # public fixture, deliberately not a real secret
MODES=('retained_roundtrip','consumer_exception','idle_readonly_write','active_readonly_write','control_write','timeout')

def emit(name,mode,**fields):probe.emit(name,mode=mode,**fields)
def parked(k,backend,mode,cycle):
    if k.state!='PARKED_ENCRYPTED':raise RuntimeError('key not encrypted-idle')
    backend.assert_locked()
    if ctypes.string_at(backend._page.address,32)==KEY:raise RuntimeError('idle fixture left plaintext')
    emit('SESSION_PARKED',mode,cycle=cycle,fixture_not_plaintext=True)

def child(mode):
    probe.configure_child()
    if mode=='timeout':
        emit('READY',mode,phase='OWNED_TEST_WAIT')
        while True:time.sleep(1)
    backend=WindowsMemoryBackend(case=mode)
    if mode=='control_write':
        try:
            backend.store(KEY);backend.writable();ctypes.memset(backend._page.address,90,1)
            if ctypes.string_at(backend._page.address,1)!=b'Z':raise RuntimeError('positive write failed')
            emit('CONTROL_READBACK',mode,verified=True);return 0
        finally:backend.wipe_release()
    k=RetainedSessionKey(backend,KEY)
    try:
        parked(k,backend,mode,0)
        if mode=='retained_roundtrip':
            for i in range(1,4):
                with k.use() as view:
                    if bytes(view)!=KEY or not view.readonly:raise RuntimeError('session key changed')
                    emit('SAME_FIXTURE',mode,cycle=i,readonly=True)
                parked(k,backend,mode,i)
            return 0
        if mode=='consumer_exception':
            try:
                with k.use() as view:
                    if bytes(view)!=KEY:raise RuntimeError('wrong initial fixture')
                    raise ValueError('synthetic consumer interruption')
            except ValueError:emit('CONSUMER_EXCEPTION',mode,expected=True)
            parked(k,backend,mode,1)
            with k.use() as view:
                if bytes(view)!=KEY:raise RuntimeError('key lost after consumer exception')
                emit('SAME_FIXTURE',mode,cycle=2,readonly=True)
            parked(k,backend,mode,2);return 0
        phase='IDLE_CIPHERTEXT' if mode=='idle_readonly_write' else 'ACTIVE_PLAINTEXT'
        def attempt():
            emit('READY',mode,phase=phase)
            try:ctypes.memset(backend._page.address,1,1)
            except OSError as e:
                if 'access violation' not in str(e).lower():raise
                emit('ACCESS_VIOLATION',mode,phase=phase,origin='ctypes_SEH');return 31
            emit('ACCESS_SUCCEEDED',mode,phase=phase);return 2
        if mode=='active_readonly_write':
            with k.use() as view:
                if bytes(view)!=KEY:raise RuntimeError('active key mismatch')
                return attempt()
        return attempt()
    finally:k.close()

def assess(rows):
    if len(rows)!=6 or [r['mode'] for r in rows]!=list(MODES):raise ValueError('exact case inventory')
    checks={}
    for row in rows:
        mode=row['mode'];ev=row['events'];ok=row['reaped'] is True and row['stderr']=='' and type(row['exit']) is int and not row.get('tool_error')
        if mode=='timeout':
            checks[mode]=bool(ok and row['timed_out'] is True and row['exit']!=0 and ev==[dict(event='READY',mode=mode,phase='OWNED_TEST_WAIT')]);continue
        ok=ok and row['timed_out'] is False and all(e.get('mode')==mode for e in ev)
        api=[e for e in ev if e['event']=='API_CALL'];crypt=[e for e in ev if e['event']=='MEMORY_CRYPT']
        ok=ok and bool(api) and ev[-1]==api[-1] and api[-1].get('operation')=='VirtualFree'
        ok=ok and all(e.get('succeeded') is True and type(e.get('win32_error')) is int and e['win32_error']==0 for e in api+crypt)
        ok=ok and not any(e.get('phase')=='protect:none' or e['event']=='ACCESS_SUCCEEDED' for e in ev)
        zero=[i for i,e in enumerate(ev) if e['event']=='MEMORY_ZEROED' and e.get('bytes')==4096 and e.get('readback_bytes')==4096]
        unlock=[i for i,e in enumerate(ev) if e.get('operation')=='VirtualUnlock']
        locks=[e for e in api if e.get('operation')=='VirtualLock']
        ok=ok and len(zero)==len(unlock)==len(locks)==1 and zero[0]<unlock[0]<len(ev)-1
        guards=[e for e in ev if e['event']=='PAGE_STATE' and e.get('phase')=='session_lock_guard']
        ok=ok and bool(guards) and all(e.get('valid') is True and e.get('locked') is True for e in guards)
        if mode=='control_write':
            ok=ok and row['exit']==0 and not crypt and any(e['event']=='CONTROL_READBACK' and e.get('verified') is True for e in ev)
        else:
            ok=ok and bool(crypt) and all(e.get('scope')=='SAME_PROCESS' and e.get('bytes')==4096 for e in crypt)
            expected={'retained_roundtrip':3,'consumer_exception':2,'idle_readonly_write':0,'active_readonly_write':1}[mode]
            ok=ok and [e['operation'] for e in crypt]==['CryptProtectMemory']+['CryptUnprotectMemory','CryptProtectMemory']*expected
            parks=[e for e in ev if e['event']=='SESSION_PARKED'];matches=[e for e in ev if e['event']=='SAME_FIXTURE']
            ok=ok and bool(parks) and all(e.get('fixture_not_plaintext') is True for e in parks)
            ok=ok and all(e.get('readonly') is True for e in matches)
            observed=[]
            for e in ev:
                if e['event']=='MEMORY_CRYPT':observed.append('P' if e['operation']=='CryptProtectMemory' else 'U')
                elif e['event']=='SESSION_PARKED':observed.append('IDLE'+str(e.get('cycle')))
                elif e['event']=='SAME_FIXTURE':observed.append('KEY'+str(e.get('cycle')))
                elif e['event']=='CONSUMER_EXCEPTION':observed.append('EXCEPTION')
                elif e['event'] in ('READY','ACCESS_VIOLATION'):observed.append(e['event']+':'+str(e.get('phase')))
            expected_order={
                'retained_roundtrip':['P','IDLE0','U','KEY1','P','IDLE1','U','KEY2','P','IDLE2','U','KEY3','P','IDLE3'],
                'consumer_exception':['P','IDLE0','U','P','EXCEPTION','IDLE1','U','KEY2','P','IDLE2'],
                'idle_readonly_write':['P','IDLE0','READY:IDLE_CIPHERTEXT','ACCESS_VIOLATION:IDLE_CIPHERTEXT'],
                'active_readonly_write':['P','IDLE0','U','READY:ACTIVE_PLAINTEXT','ACCESS_VIOLATION:ACTIVE_PLAINTEXT','P'],
            }
            ok=ok and observed==expected_order[mode]
            if mode=='retained_roundtrip':ok=ok and row['exit']==0 and [e.get('cycle') for e in parks]==[0,1,2,3] and [e.get('cycle') for e in matches]==[1,2,3]
            elif mode=='consumer_exception':ok=ok and row['exit']==0 and [e.get('cycle') for e in parks]==[0,1,2] and [e.get('cycle') for e in matches]==[2] and any(e['event']=='CONSUMER_EXCEPTION' and e.get('expected') is True for e in ev)
            else:
                phase='IDLE_CIPHERTEXT' if mode=='idle_readonly_write' else 'ACTIVE_PLAINTEXT'
                ready=[i for i,e in enumerate(ev) if e['event']=='READY' and e.get('phase')==phase]
                denied=[i for i,e in enumerate(ev) if e['event']=='ACCESS_VIOLATION' and e.get('phase')==phase and e.get('origin')=='ctypes_SEH']
                ok=ok and row['exit']==31 and len(ready)==len(denied)==1 and ready[0]<denied[0]<zero[0]
        checks[mode]=bool(ok)
    return checks

def run_child(mode):
    start=time.monotonic();env={k:os.environ[k] for k in ('SystemRoot','WINDIR','TEMP','TMP','PATH','LANG') if k in os.environ}
    p=subprocess.Popen([sys.executable,'-I','-B',str(Path(__file__).resolve()),'--child',mode],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,close_fds=True)
    timeout=False
    try:
        try:out,err=p.communicate(timeout=5 if mode=='timeout' else 30)
        except subprocess.TimeoutExpired:timeout=True;p.kill();out,err=p.communicate(timeout=5)
    finally:
        if p.poll() is None:p.kill();p.wait(timeout=5)
    row=dict(mode=mode,exit=p.returncode,timed_out=timeout,reaped=p.poll() is not None,elapsed_seconds=round(time.monotonic()-start,3),events=[],stderr=err[:8192].decode('utf-8','replace'))
    if len(out)>65536 or len(err)>8192:row['tool_error']='bounded output exceeded'
    else:
        try:row['events']=[json.loads(l) for l in out.decode().splitlines()]
        except (UnicodeDecodeError,ValueError):
            row['tool_error']='invalid child output';row['unparsed_public_fixture_output']=out.decode('utf-8','replace')
    return row

def run(destination):
    d=Path(destination);d.mkdir(parents=True,exist_ok=False)
    r=dict(schema=1,status='STOP',scope='PUBLIC_FIXTURE_WINDOWS_RETAINED_SESSION_KEY_API_ONLY',product_accepted=False,product_executed=False,product_backend_implemented=False,all_secret_copies_protected=False,DPAPI_integrity_assumed=False)
    try:
        if sys.platform!='win32' or platform.machine().lower() not in ('amd64','x86_64'):raise RuntimeError('Windows/x64 required; no fallback')
        if platform.python_version()!='3.12.3' or probe.mmap.PAGESIZE!=4096:raise RuntimeError('pinned Python3.12.3/page4096 required')
        r['source_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        r['ci']={k:os.environ.get(k) for k in ('GITHUB_SHA','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','ImageOS','ImageVersion')}
        r['environment']=dict(system=platform.system(),machine=platform.machine(),python=platform.python_version(),page_size=probe.mmap.PAGESIZE,privilege=probe.privilege())
        r['results']=[]
        for mode in MODES:
            try:row=run_child(mode)
            except Exception as e:row=dict(mode=mode,exit=None,timed_out=False,reaped=False,events=[],stderr='',tool_error=type(e).__name__+':'+str(e)[:300])
            r['results'].append(row)
        r['checks']=assess(r['results'])
        r['status']='SCOPED_RETAINED_SESSION_API_PASS_PRODUCT_NOT_ACCEPTED' if all(r['checks'].values()) else 'FAIL'
    except Exception as e:r['error']=dict(type=type(e).__name__,message=str(e)[:500])
    (d/'RESULT.json').write_text(json.dumps(r,indent=2)+'\n');return 0 if r['status']=='SCOPED_RETAINED_SESSION_API_PASS_PRODUCT_NOT_ACCEPTED' else 1

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);g=p.add_mutually_exclusive_group(required=True);g.add_argument('--child',choices=MODES);g.add_argument('--output');a=p.parse_args();os.umask(0o077)
    raise SystemExit(child(a.child) if a.child else run(a.output))
