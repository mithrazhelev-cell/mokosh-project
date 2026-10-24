"""Portable unchanged-baseline unittest worker; not a GUI acceptance runner.

Call with an isolated interpreter (-I -B), an expendable 263-file source copy,
and a new output directory outside that copy. No source/test overlay is applied.
The controller owns platform/runtime qualification and subprocess timeout.
"""
from __future__ import annotations
import argparse,hashlib,importlib.machinery,importlib.metadata,json,os,platform,stat,sys,time,traceback,types,unittest
from pathlib import Path

SOURCE_SHA256='92e159ed818bc6fbf858549452ad78fd0b238f9d8193ac9842147555afb3dcca'
SOURCE_FILES=263
SOURCE_BYTES=5223645
TEST_MODULES=92
TESTS=2509
DEPENDENCIES=('cryptography','argon2-cffi','argon2-cffi-bindings','cffi','pycparser')

def identity(project):
    rows=[];digest=hashlib.sha256();total=0
    for path in sorted(project.rglob('*'),key=lambda p:p.relative_to(project).as_posix()):
        if path.is_symlink():raise ValueError('Source symlink rejected: '+str(path))
        if not path.is_file():continue
        name=path.relative_to(project).as_posix();data=path.read_bytes();encoded=name.encode('utf-8')
        digest.update(len(encoded).to_bytes(4,'big')+encoded+len(data).to_bytes(8,'big')+data)
        total+=len(data)
        rows.append({'path':name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),
                     'mode':stat.S_IMODE(path.stat().st_mode)})
    return {'files':len(rows),'bytes':total,'canonical_sha256':digest.hexdigest(),'records':rows}

def require(value,detail):
    if not value:raise ValueError(detail)

def main():
    parser=argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('--project',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    project=args.project.resolve(strict=True);output=args.output.resolve()
    require(output!=project and project not in output.parents,'Output must be outside disposable source copy')
    output.mkdir(mode=0o700,parents=True,exist_ok=False)
    report={'result':'INCOMPLETE','scope':'FROZEN_BASELINE_UNITTEST_ONLY_NO_OVERLAY',
      'runtime':{'python':sys.version,'executable':sys.executable,'prefix':sys.prefix,
        'platform':platform.platform(),'os_name':os.name,'isolated':bool(sys.flags.isolated),
        'dont_write_bytecode':bool(sys.dont_write_bytecode)},
      'expected_source_sha256':SOURCE_SHA256,'test_modules':0,'discovered':0,'tests_run':0,
      'successful_test_ids':[],'failures':[],'errors':[],'skipped':[],
      'expected_failures':[],'unexpected_successes':[],
      'native_GUI_acceptance':'NOT_TESTED','physical_GUI':'NOT_TESTED',
      'callback_reporting_acceptance':'NOT_TESTED_BY_THIS_UNIT_SUITE',
      'known_issue':'D005 parent return remains OPEN; unittest PASS cannot accept native window behavior.',
      'R3_candidate_tested':False,'source_overlay_applied':False,'live_apply':False}
    before=None;started=time.monotonic()
    try:
        require(sys.flags.isolated and sys.dont_write_bytecode,'Explicit -I -B interpreter flags required')
        report['runtime']['dependencies']={name:importlib.metadata.version(name) for name in DEPENDENCIES}
        before=identity(project);report['source_before']=before
        require((before['files'],before['bytes'],before['canonical_sha256'])==(SOURCE_FILES,SOURCE_BYTES,SOURCE_SHA256),
                'Exact frozen baseline source identity differs')
        source_bytes={r['path']:(project/r['path']).read_bytes() for r in before['records']}
        for name,data in source_bytes.items():
            if name.endswith('.py'):compile(data,name,'exec')
        report['python_files_compiled']=sum(n.endswith('.py') for n in source_bytes)
        os.chdir(project)
        data_dir=output/'isolated_test_data';data_dir.mkdir(mode=0o700)
        os.environ['MOKOSH_DATA_DIR']=str(data_dir)
        sys.path.insert(0,str(project))
        # This source tree intentionally has no tests/__init__.py. Bind its
        # namespace explicitly so unrelated installed "tests" cannot shadow it.
        package=types.ModuleType('tests');package.__path__=[str(project/'tests')]
        package.__spec__=importlib.machinery.ModuleSpec('tests',loader=None,is_package=True)
        sys.modules['tests']=package
        modules=sorted('tests.'+'.'.join(p.relative_to(project/'tests').with_suffix('').parts)
                       for p in (project/'tests').rglob('test*.py'))
        report['test_module_names']=modules;report['test_modules']=len(modules)
        require(len(modules)==TEST_MODULES,'Expected all92 frozen test modules')
        suite=unittest.defaultTestLoader.loadTestsFromNames(modules)
        report['discovered']=suite.countTestCases()
        report['discovered_count_matches_expected']=report['discovered']==TESTS
        # Run any discovery failure placeholders so their original import
        # tracebacks reach FULL_TESTS.log; final acceptance still requires2509.
        class Result(unittest.TextTestResult):
            def addSuccess(self,test):
                report['successful_test_ids'].append(test.id());super().addSuccess(test)
        with (output/'FULL_TESTS.log').open('x',encoding='utf-8') as stream:
            result=unittest.TextTestRunner(stream=stream,verbosity=2,resultclass=Result).run(suite)
        report.update(tests_run=result.testsRun,
          failures=[{'test':t.id(),'traceback':s} for t,s in result.failures],
          errors=[{'test':t.id(),'traceback':s} for t,s in result.errors],
          skipped=[{'test':t.id(),'reason':s} for t,s in result.skipped],
          expected_failures=[{'test':t.id(),'traceback':s} for t,s in result.expectedFailures],
          unexpected_successes=[t.id() for t in result.unexpectedSuccesses])
    except BaseException as error:
        report['runner_error']={'type':type(error).__name__,'message':str(error),
                                'traceback':traceback.format_exc()}
    finally:
        try:
            report['source_after']=identity(project)
            report['source_files_unchanged']=before is not None and report['source_after']==before
        except BaseException as error:
            report['final_identity_error']={'type':type(error).__name__,'message':str(error)}
            report['source_files_unchanged']=False
        report['duration_seconds']=round(time.monotonic()-started,3)
        for name,field in (('failure_count','failures'),('error_count','errors'),('skip_count','skipped')):
            report[name]=len(report[field])
        report['successful_test_count']=len(report['successful_test_ids'])
        report['unique_successful_test_count']=len(set(report['successful_test_ids']))
        tk_module=sys.modules.get('tkinter');native_tk=sys.modules.get('_tkinter')
        report['runtime']['loaded_tkinter']={
          'module_path':getattr(tk_module,'__file__',None),
          'compiled_Tk_version':getattr(tk_module,'TkVersion',None),
          'native_extension_path':getattr(native_tk,'__file__',None)}
        success=(not report.get('runner_error') and report['source_files_unchanged'] and
          report['discovered']==report['tests_run']==report['successful_test_count']==
          report['unique_successful_test_count']==TESTS and
          not any(report[n] for n in ('failures','errors','skipped','expected_failures','unexpected_successes')))
        report['result']='PASS_FROZEN_BASELINE_2509' if success else 'FAIL_FROZEN_BASELINE_AUDIT'
        (output/'RESULT.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        print(json.dumps({k:report[k] for k in ('result','test_modules','discovered','tests_run',
          'successful_test_count','failure_count','error_count','skip_count','source_files_unchanged',
          'duration_seconds','native_GUI_acceptance')},ensure_ascii=False),flush=True)
    return 0 if success else 1

if __name__=='__main__':raise SystemExit(main())
