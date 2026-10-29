"""Synthetic evaluator controls only. Nothing here performs native file operations."""
from __future__ import annotations
import copy
import hashlib
import json
from pathlib import Path
from src.evaluate_records import (DARWIN_FLAGS, ORACLE_SHA256, CONTRACT_SHA256,
                                 SCOPE, PAYLOADS, OPEN_OPS, RecordRejected,
                                 evaluate_records)

def documents(workroot):
    root=Path(workroot)
    return (json.loads((root/'ORACLE.json').read_text(encoding='utf-8')),
            json.loads((root/'RECORD_CONTRACT.json').read_text(encoding='utf-8')))

def build_synthetic_fixture(oracle, contract):
    """A plainly labeled serialization fixture, not measured Darwin results."""
    runtime={'system':'Darwin','sys_platform':'darwin','implementation':'CPython',
             'machine':'arm64','isolated':True,'dont_write_bytecode':True,
             'optimize':0,'pointer_bytes':8,'python_version':[3,12,3],
             'uid':501,'euid':501,'flag_values':dict(DARWIN_FLAGS),
             'filesystem_type':'NOT_COLLECTED',
             'volume_metadata':{'status':'SYNTHETIC_NO_VOLUME_MEASUREMENT'},
             'fixture_metadata':'EXPLICITLY_SYNTHETIC_NOT_MEASURED'}
    cases=[]
    for ci,(spec,sem) in enumerate(zip(contract['cases'],oracle['cases'])):
        labels=[s['expect']['read_label'] for s in spec['steps'] if s['op']=='pread']
        parent={k:k for k in labels}
        def find(k):
            while parent[k]!=k: k=parent[k]
            return k
        for relation,left,right in spec['identity_relations']:
            if relation=='same': parent[find(right)]=find(left)
        groups={}
        for label in labels:
            root=find(label)
            if root not in groups: groups[root]=1000+ci*100+len(groups)
        events=[];reads=[];snapshots=[];active={}
        for n,step in enumerate(spec['steps']):
            e={k:copy.deepcopy(step[k]) for k in ('op','role','leaf','phase','args')}
            e['index']=n
            exp=step['expect']
            if step['op'] in OPEN_OPS:
                fd=5
                while fd in active.values(): fd+=1
                active[step['role']]=fd
                e['return']=fd
                flags=0
                for name in contract['open_flag_policy'][step['op']]: flags |= DARWIN_FLAGS[name]
                e.update(actual_flags=flags,actual_inheritable=False,
                         actual_mode=384 if step['op']=='create' else 0)
            else:
                e['return']=exp['return']
            e['errno']=exp['errno'];e['success']=e['return']>=0 and e['errno']==0
            events.append(e)
            if step['op']=='pread':
                label=exp['read_label'];payload=PAYLOADS[exp['read_payload']]
                reads.append({'event_index':n,'role':step['role'],'phase':step['phase'],
                              'count':4096,'offset':0,'hex':payload.hex(),
                              'sha256':hashlib.sha256(payload).hexdigest(),
                              'identity':{'observed_by':'fstat','st_dev':50,
                                          'st_ino':groups[find(label)],'st_size':4096,
                                          'st_nlink':0 if spec['id']=='M07' and label=='held_after' else 1,
                                          'st_mode':0o100600,'st_uid':501}})
            if step['op']=='path_stat':
                snapshots.append({'event_index':n,'role':step['role'],'phase':step['phase'],
                                  'leaf':step['leaf'],'exists':False,'errno':2})
            if step['op']=='close': del active[step['role']]
        cases.append({'id':spec['id'],'category':sem['category'],'events':events,
                      'reads':reads,'snapshots':snapshots,'complete':True})
    return {'schema':1,'origin':'SYNTHETIC_NOT_NATIVE','scope':SCOPE,
            'oracle_sha256':ORACLE_SHA256,'record_contract_sha256':CONTRACT_SHA256,
            'runtime':runtime,'case_records':cases,'case_count':7,
            'application_fix':False,'FS15_accepted':False,'physical_acceptance':False}

def run_self_tests(workroot):
    oracle,contract=documents(workroot)
    fixture=build_synthetic_fixture(oracle,contract)
    positive=evaluate_records(fixture,oracle,contract)
    controls=[]
    def reject(name,reason,mutate):
        changed=copy.deepcopy(fixture);mutate(changed)
        try: evaluate_records(changed,oracle,contract)
        except RecordRejected as exc:
            if exc.reason!=reason:
                raise AssertionError(name+': wrong rejection reason '+exc.reason+' expected '+reason) from exc
            controls.append({'name':name,'detected':True,'expected_reason':reason,'actual_reason':exc.reason})
        else: raise AssertionError(name+': mutation was accepted')
    def case(r,cid):return next(c for c in r['case_records'] if c['id']==cid)
    def event(r,cid,op):return next(e for e in case(r,cid)['events'] if e['op']==op)
    def read_by_label(r,cid,label):
        spec=next(c for c in contract['cases'] if c['id']==cid)
        index=next(i for i,s in enumerate(spec['steps']) if s['expect'].get('read_label')==label)
        return next(z for z in case(r,cid)['reads'] if z['event_index']==index)
    def payload_change(r,cid,label,payload):
        z=read_by_label(r,cid,label);z['hex']=payload.hex();z['sha256']=hashlib.sha256(payload).hexdigest()
    reject('M01_boolean_case_count','CASE_COUNT',lambda r:r.__setitem__('case_count',True))
    reject('M02_missing_case','CASE_COUNT',lambda r:r['case_records'].pop())
    reject('M03_reordered_cases','CASE_ORDER',lambda r:r['case_records'].reverse())
    reject('M04_missing_rename_attempt','EVENT_COUNT',lambda r:case(r,'M02')['events'].pop(5))
    reject('M05_boolean_errno','EVENT_INTEGER',lambda r:event(r,'M03','rename_excl').__setitem__('errno',False))
    reject('M06_ENOENT_is_not_collision','EVENT_ERRNO',lambda r:event(r,'M03','rename_excl').__setitem__('errno',2))
    def deny_all(r):
        e=event(r,'M02','rename_excl');e.update({'return':-1,'errno':13,'success':False})
    reject('M07_deny_all_not_function','EVENT_ERRNO',deny_all)
    reject('M08_collision_target_changed','READ_PAYLOAD',lambda r:payload_change(r,'M03','target_after',PAYLOADS['B']))
    reject('M09_held_path_binding_wrong','READ_PAYLOAD',lambda r:payload_change(r,'M05','held_after',PAYLOADS['B']))
    reject('M10_same_inode_claim_unsupported','IDENTITY_RELATION',lambda r:read_by_label(r,'M06','held_after')['identity'].__setitem__('st_ino',999999))
    reject('M11_limitation_labeled_prevention','CATEGORY',lambda r:case(r,'M06').__setitem__('category','PREVENTION_OBSERVATION'))
    reject('M12_replacement_rename_flag','EVENT_INTENT',lambda r:event(r,'M02','rename_excl')['args'].__setitem__('flags',0))
    reject('M13_failed_close','EVENT_ERRNO',lambda r:event(r,'M01','close').__setitem__('errno',5))
    reject('M14_missing_read','READ_COUNT',lambda r:case(r,'M01')['reads'].pop())
    reject('M15_unbound_facts_claim','CASE_FIELDS',lambda r:case(r,'M05').__setitem__('facts',{'prevention':True}))
    def linux_native(r):r['origin']='NATIVE_DARWIN_OWN_FILES';r['runtime']['system']='Linux';r['runtime']['sys_platform']='linux'
    reject('M16_Linux_cannot_be_native_Darwin','RUNTIME_GUARD',linux_native)
    reject('M17_wrong_frozen_oracle','ORACLE_BINDING',lambda r:r.__setitem__('oracle_sha256','0'*64))
    reject('M18_scope_escalation','SCOPE_ESCALATION',lambda r:r.__setitem__('FS15_accepted',True))
    reject('M19_open_without_nofollow','OPEN_FLAGS',lambda r:event(r,'M01','create').__setitem__('actual_flags',DARWIN_FLAGS['O_RDWR']|DARWIN_FLAGS['O_CREAT']|DARWIN_FLAGS['O_EXCL']|DARWIN_FLAGS['O_CLOEXEC']))
    reject('M20_boolean_offset','EVENT_INTENT',lambda r:event(r,'M01','pread')['args'].__setitem__('offset',False))
    reject('M21_missing_unlink_path_proof','SNAPSHOT_COUNT',lambda r:case(r,'M07')['snapshots'].clear())
    reject('M22_wrong_unlink_link_count','IDENTITY_SIZE_LINKS',lambda r:read_by_label(r,'M07','held_after')['identity'].__setitem__('st_nlink',1))
    reject('M23_inheritable_descriptor','OPEN_INHERITABLE',lambda r:event(r,'M01','create').__setitem__('actual_inheritable',True))
    reject('M24_false_completion','INCOMPLETE',lambda r:case(r,'M07').__setitem__('complete',False))
    return {'schema':1,'status':'PASS_PURE_SYNTHETIC_EVALUATOR_GUARDS',
            'positive_synthetic_fixture':positive,'mutation_count':len(controls),
            'mutations':controls,'native_cases_executed':0,'application_imports':0,
            'workflow_runs':0,'application_fix':False,'FS15_accepted':False,
            'limit':'Synthetic record mutations test evaluator rejection; they are not native Darwin observations.'}
