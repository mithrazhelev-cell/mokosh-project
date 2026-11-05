"""Pinned public-fixture memory experiment; no product imports or dependencies."""
import argparse,hashlib,importlib.util,json,os,subprocess,sys
from pathlib import Path
NAMES={'probe.py','test_probe.py','session_key.py','test_session_key.py','test_windows_binding.py','native_session_probe.py','test_native_session_probe.py','run_session_ci.py','SCOPE_SESSION.txt'}
MODELS="""import io,json,sys,unittest
from pathlib import Path
r=Path(sys.argv[1]);sys.path.insert(0,str(r))
groups={'test_probe':38,'test_session_key':21,'test_windows_binding':9,'test_native_session_probe':15}
suite=unittest.TestSuite();ids=[]
def walk(s):
 if isinstance(s,unittest.TestSuite):
  for t in s:yield from walk(t)
 else:yield s.id()
for name,count in groups.items():
 s=unittest.defaultTestLoader.loadTestsFromName(name);cases=list(walk(s))
 if len(cases)!=count:raise RuntimeError('case inventory:'+name)
 ids.extend(cases);suite.addTest(s)
if len(ids)!=83 or len(set(ids))!=83:raise RuntimeError('duplicate case inventory')
stream=io.StringIO();result=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
print(stream.getvalue());print('MODEL_RESULT='+json.dumps(dict(run=result.testsRun,unique=len(set(ids)),case_ids=ids,failures=len(result.failures),errors=len(result.errors),skipped=len(result.skipped),success=result.wasSuccessful())))
raise SystemExit(0 if result.wasSuccessful() and not result.skipped else 1)
"""

def main(destination):
    root=Path(__file__).resolve().parent;d=Path(destination);d.mkdir(parents=True,exist_ok=False)
    s=dict(status='STOP',product_accepted=False,product_code_imported=False,product_backend_implemented=False,prior_R3_run=42000005469,prior_R2_failure_retained=True)
    try:
        inputs=json.loads((root/'INPUTS_SESSION.json').read_text())
        if set(inputs)!=NAMES:raise ValueError('input inventory')
        for name,digest in inputs.items():
            p=root/name
            if not p.is_file() or p.is_symlink() or hashlib.sha256(p.read_bytes()).hexdigest()!=digest:raise ValueError('input mismatch:'+name)
        s['verified_inputs']=inputs
        p=subprocess.run([sys.executable,'-I','-B','-c',MODELS,str(root)],stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=30)
        log=p.stdout+p.stderr;(d/'ORACLE_TESTS.log').write_text(log,encoding='utf-8')
        result=json.loads(next(line for line in log.splitlines() if line.startswith('MODEL_RESULT=')).split('=',1)[1]);s['models']=result
        if p.returncode!=0 or result['run']!=83 or result['unique']!=83 or not result['success'] or result['skipped']:raise RuntimeError('models failed; no native run')
        spec=importlib.util.spec_from_file_location('retained_session_native',root/'native_session_probe.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        s['native_exit']=module.run(d/'native')
        s['status']='SCOPED_RETAINED_SESSION_API_PASS_PRODUCT_NOT_ACCEPTED' if s['native_exit']==0 else 'FAIL_OR_STOP_NATIVE_REVIEW_REQUIRED'
    except Exception as e:s['error']=dict(type=type(e).__name__,message=str(e)[:500])
    (d/'SUMMARY.json').write_text(json.dumps(s,indent=2)+'\n');print(json.dumps(s));return 0 if s['status']=='SCOPED_RETAINED_SESSION_API_PASS_PRODUCT_NOT_ACCEPTED' else 1

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',required=True);a=p.parse_args();os.umask(0o077);raise SystemExit(main(a.output))
