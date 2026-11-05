"""Pinned synthetic Windows protocol qualification; never import MOKOSH."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys


def verify(root):
    manifest=json.loads((root/'INPUTS.json').read_text())
    expected={'probe.py','test_probe.py','SCOPE.txt','safe_probe.py','test_safe_probe.py','run_safe_ci.py'}
    if set(manifest)!=expected:raise ValueError('input inventory')
    for name,digest in manifest.items():
        p=root/name
        if not p.is_file() or p.is_symlink() or hashlib.sha256(p.read_bytes()).hexdigest()!=digest:raise ValueError('input mismatch:'+name)
    return manifest


def main(destination):
    root=Path(__file__).resolve().parent;d=Path(destination);d.mkdir(parents=True,exist_ok=False)
    summary=dict(status='STOP',product_accepted=False,product_code_imported=False,physical_GUI_tested=False,
                 product_backend_implemented=False,baseline_unsafe_R2_status='FAIL_RETAINED_RUN41995657846',model_suites=[])
    logs=[]
    try:
        summary['verified_inputs']=verify(root)
        for name,count in [('test_probe.py',38),('test_safe_probe.py',18)]:
            p=subprocess.run([sys.executable,'-I','-B',str(root/name)],stdin=subprocess.DEVNULL,
                             capture_output=True,text=True,timeout=30,check=False)
            log=p.stdout+p.stderr;logs.append('SUITE='+name+'\n'+log)
            summary['model_suites'].append(dict(name=name,expected=count,exit=p.returncode))
            if p.returncode!=0 or not re.search(r'(?m)^Ran '+str(count)+r' tests in [0-9.]+s$',log) or not re.search(r'(?m)^OK$',log):
                raise RuntimeError('model suite refused:'+name)
        spec=importlib.util.spec_from_file_location('safe_protocol',root/'safe_probe.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        summary['native_exit']=module.run(d/'native')
        summary['status']='SCOPED_EMPTY_PARK_PROTOCOL_PASS_PRODUCT_NOT_ACCEPTED' if summary['native_exit']==0 else 'FAIL_OR_STOP_NATIVE_REVIEW_REQUIRED'
    except Exception as exc:summary['error']=dict(type=type(exc).__name__,message=str(exc)[:500])
    (d/'ORACLE_TESTS.log').write_text('\n'.join(logs),encoding='utf-8')
    (d/'SUMMARY.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps(summary));return 0 if summary['status']=='SCOPED_EMPTY_PARK_PROTOCOL_PASS_PRODUCT_NOT_ACCEPTED' else 1


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',required=True);os.umask(0o077)
    raise SystemExit(main(p.parse_args().output))
