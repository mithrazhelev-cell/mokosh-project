"""Pure runtime/ABI controls with explicit fake functions, never Darwin syscalls."""
from __future__ import annotations
import copy
import ctypes
import stat
from types import SimpleNamespace
from unittest.mock import patch
from src import darwin_file_api as api

def eligible_fixture():
    return {'system':'Darwin','sys_platform':'darwin','os_name':'posix',
            'implementation':'CPython','python_minor':[3,12],'python_version':[3,12,3],
            'pointer_bytes':8,'int_bytes':4,'uint_bytes':4,'machine':'arm64',
            'isolated':True,'dont_write_bytecode':True,'optimize':0,
            'uid':501,'euid':501,'flag_values':dict(api.DARWIN_FLAG_VALUES),
            'dir_fd_support':{'open':True,'stat':True,'unlink':True}}

def run_binding_checks():
    controls=[]
    def done(name): controls.append(name)
    meta=eligible_fixture()
    if api.runtime_rejection_reasons(meta): raise AssertionError('eligible synthetic metadata refused')
    done('eligible_synthetic_runtime_no_library')
    variations=[('system','Linux'),('sys_platform','linux'),('os_name','nt'),
                ('implementation','PyPy'),('python_minor',[3,11]),
                ('python_minor',[True,12]),('pointer_bytes',4),('int_bytes',8),
                ('uint_bytes',8),('machine','aarch64'),('isolated',False),
                ('dont_write_bytecode',False),('optimize',1),('uid',0),('euid',502)]
    for n,(key,value) in enumerate(variations):
        changed=copy.deepcopy(meta);changed[key]=value
        if not api.runtime_rejection_reasons(changed): raise AssertionError('bad runtime accepted: '+key)
        done('runtime_reject_%02d_%s'%(n+1,key))
    for name,value in [('missing',None),('boolean',True),('wrong_abi',0)]:
        changed=copy.deepcopy(meta)
        if name=='missing': changed['flag_values'].pop('O_NOFOLLOW')
        else: changed['flag_values']['O_NOFOLLOW']=value
        if not api.runtime_rejection_reasons(changed): raise AssertionError('bad flags accepted: '+name)
        done('runtime_flag_'+name)
    changed=copy.deepcopy(meta);changed['dir_fd_support']['unlink']=False
    if not api.runtime_rejection_reasons(changed): raise AssertionError('missingdirfd support accepted')
    done('missing_dirfd_support_refused')
    if api.checked_leaf('published-Δ-Ж.bin').hex()!='7075626c69736865642dce942dd0962e62696e':
        raise AssertionError('Unicode encoding differs')
    done('fixed_unicode_leaf_exact_utf8')
    for bad in ('../stage.bin','/stage.bin','stage.bin/other','stage.bin\x00','unlisted.bin',False):
        try: api.checked_leaf(bad)
        except ValueError: pass
        else: raise AssertionError('foreign/unlisted leaf accepted')
    done('six_unlisted_leaf_controls')
    for bad in (False,0,-1,2**31):
        try: api.NativeApiError('renameatx_np',bad)
        except ValueError: pass
        else: raise AssertionError('invalid native errno accepted')
    done('four_invalid_errno_controls')
    invalid=copy.deepcopy(meta);invalid['system']='Linux'
    with patch.object(api,'runtime_metadata',return_value=invalid),patch.object(api.ctypes,'CDLL') as dll:
        try: api.DarwinFileApi()
        except RuntimeError: pass
        else: raise AssertionError('wrong host constructed nativebinding')
        if dll.call_count: raise AssertionError('DLL loaded before hostguard')
    done('wrong_host_stops_before_library_load')
    class FakeRename:
        def __init__(self): self.result=0;self.calls=[]
        def __call__(self,*args): self.calls.append(args);return self.result
    fn=FakeRename();lib=SimpleNamespace(renameatx_np=fn)
    with patch.object(api,'runtime_metadata',return_value=meta),patch.object(api.ctypes,'CDLL',return_value=lib) as dll:
        binding=api.DarwinFileApi()
        dll.assert_called_once_with('/usr/lib/libSystem.B.dylib',use_errno=True)
        if fn.argtypes != [ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint] or fn.restype is not ctypes.c_int:
            raise AssertionError('renameatx_np ABI differs')
        done('mocked_exact_binding_abi_and_library_path')
        with patch.object(api.os,'fstat',return_value=SimpleNamespace(st_mode=stat.S_IFDIR|0o700)):
            if binding.rename_excl(7,'stage.bin','published-Δ-Ж.bin')!=0:
                raise AssertionError('mocked rename success differs')
            if fn.calls[-1]!=(7,b'stage.bin',7,'published-Δ-Ж.bin'.encode('utf-8'),4):
                raise AssertionError('directory/UTF8/exclusiveflag args differ')
            done('mocked_rename_exact_utf8_dirfd_exclusive_args')
            fn.result=-1
            with patch.object(api.ctypes,'get_errno',return_value=17):
                try: binding.rename_excl(7,'stage.bin','published.bin')
                except api.NativeApiError as exc:
                    if type(exc.errno) is not int or exc.errno!=17: raise AssertionError('errno notretained')
                else: raise AssertionError('native error became success')
            done('mocked_collision_errno_retained')
            with patch.object(api.ctypes,'get_errno',return_value=0):
                try: binding.rename_excl(7,'stage.bin','published.bin')
                except ValueError: pass
                else: raise AssertionError('missing errno accepted asnativefailure')
            done('mocked_failure_without_errno_refused')
            fn.result=1
            try: binding.rename_excl(7,'stage.bin','published.bin')
            except RuntimeError: pass
            else: raise AssertionError('unexpected native result accepted')
            done('mocked_unexpected_return_refused')
            before=len(fn.calls)
            for bad in (False,-1):
                try: binding.rename_excl(bad,'stage.bin','published.bin')
                except ValueError: pass
                else: raise AssertionError('invalid descriptor accepted')
            if len(fn.calls)!=before: raise AssertionError('invalid descriptor reached binding')
            done('mocked_invalid_fd_before_native_call')
        with patch.object(api.os,'fstat',return_value=SimpleNamespace(st_mode=stat.S_IFREG|0o600)):
            before=len(fn.calls)
            try: binding.rename_excl(7,'stage.bin','published.bin')
            except ValueError: pass
            else: raise AssertionError('regular FD accepted asdirectory')
            if len(fn.calls)!=before: raise AssertionError('regularFD reachedbinding')
            done('mocked_wrong_fd_type_before_native_call')
    return {'schema':1,'status':'PASS_PURE_RUNTIME_AND_MOCKED_BINDING_GUARDS',
            'count':len(controls),'names':controls,'native_calls':0,
            'native_libraries_loaded':0,'application_imports':0,
            'limit':'Metadata and mocked function objects only; no Darwin or ownership/security acceptance.'}
