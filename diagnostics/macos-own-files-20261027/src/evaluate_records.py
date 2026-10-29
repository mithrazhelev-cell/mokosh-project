"""Pure evaluator for frozen own-file diagnostics; this cannot attest record origin."""
from __future__ import annotations
import hashlib
import json
import stat

ORACLE_SHA256 = '50ce179c3c9e8c369d000ec45f9caa1ca30f63f719eecb0ba266c9b845e5c412'
CONTRACT_SHA256 = 'a747385b7753710338299b815bdcc4639023a463f02b58535ec634da6f96e858'
SCOPE = 'MACOS_OWN_FILES_DIAGNOSTIC_SEVEN_GROUPS_NOT_APPLICATION_FIX'
DARWIN_FLAGS = {'O_RDONLY':0, 'O_WRONLY':1, 'O_RDWR':2, 'O_CREAT':512,
                'O_EXCL':2048, 'O_NOFOLLOW':256, 'O_CLOEXEC':16777216,
                'O_DIRECTORY':1048576}
PAYLOADS = {'A':bytes(range(256))*16, 'B':b'B'*4096, 'C':b'C'*4096}
OPEN_OPS = {'open_dir','create','open_read','open_write'}

class RecordRejected(ValueError):
    def __init__(self, reason: str, detail: str = ''):
        self.reason = reason
        super().__init__(reason + (': '+detail if detail else ''))

def require(ok: bool, reason: str, detail: str = '') -> None:
    if not ok:
        raise RecordRejected(reason, detail)

def exact(a, b) -> bool:
    """JSON structural equality with exact types, including integer/boolean separation."""
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        return a.keys() == b.keys() and all(exact(a[k], b[k]) for k in a)
    if isinstance(a, list):
        return len(a) == len(b) and all(exact(x,y) for x,y in zip(a,b))
    return a == b

def canonical_hash(doc) -> str:
    return hashlib.sha256((json.dumps(doc,ensure_ascii=False,indent=2)+'\n').encode('utf-8')).hexdigest()

def keys(obj, wanted, reason: str) -> None:
    require(type(obj) is dict and set(obj) == set(wanted), reason)

def integer(n, minimum=0) -> bool:
    return type(n) is int and n >= minimum

def runtime_guard(runtime: dict) -> None:
    require(type(runtime) is dict, 'RUNTIME_TYPE')
    fixed = {'system':'Darwin','sys_platform':'darwin','implementation':'CPython',
             'isolated':True,'dont_write_bytecode':True,'optimize':0,'pointer_bytes':8}
    require(all(k in runtime and exact(runtime[k],v) for k,v in fixed.items()), 'RUNTIME_GUARD')
    require(runtime.get('machine') in ('arm64','x86_64'), 'RUNTIME_GUARD')
    version = runtime.get('python_version')
    require(type(version) is list and len(version)==3 and all(integer(x) for x in version)
            and version[:2]==[3,12], 'RUNTIME_GUARD')
    require(integer(runtime.get('uid'),1) and integer(runtime.get('euid'),1)
            and runtime['uid']==runtime['euid'], 'RUNTIME_GUARD')
    require(exact(runtime.get('flag_values'), DARWIN_FLAGS), 'RUNTIME_FLAGS')
    require(runtime.get('filesystem_type') == 'NOT_COLLECTED', 'FILESYSTEM_CLAIM')
    require(type(runtime.get('volume_metadata')) is dict, 'VOLUME_METADATA')

def validate_identity(identity, runtime, expected_nlink):
    keys(identity,['observed_by','st_dev','st_ino','st_size','st_nlink','st_mode','st_uid'], 'IDENTITY_FIELDS')
    require(identity['observed_by']=='fstat', 'IDENTITY_SOURCE')
    require(all(integer(identity[k]) for k in identity if k!='observed_by'), 'IDENTITY_INTEGER')
    require(identity['st_size']==4096 and identity['st_nlink']==expected_nlink, 'IDENTITY_SIZE_LINKS')
    require(identity['st_uid']==runtime['euid'], 'IDENTITY_OWNER')
    require(stat.S_ISREG(identity['st_mode']) and not (stat.S_IMODE(identity['st_mode']) & ~0o600), 'IDENTITY_MODE')
    return (identity['st_dev'],identity['st_ino'])

def evaluate_records(records: dict, oracle: dict, contract: dict) -> dict:
    """Reject incomplete/inconsistent records; matching claims need external run binding."""
    require(canonical_hash(oracle)==ORACLE_SHA256, 'ORACLE_DOCUMENT_BINDING')
    require(canonical_hash(contract)==CONTRACT_SHA256, 'CONTRACT_DOCUMENT_BINDING')
    keys(records, contract['envelope_fields'], 'ENVELOPE_FIELDS')
    require(type(records['schema']) is int and records['schema']==1, 'SCHEMA')
    require(records['scope']==SCOPE, 'SCOPE')
    require(records['oracle_sha256']==ORACLE_SHA256, 'ORACLE_BINDING')
    require(records['record_contract_sha256']==CONTRACT_SHA256, 'CONTRACT_BINDING')
    require(records['origin'] in ('SYNTHETIC_NOT_NATIVE','NATIVE_DARWIN_OWN_FILES'), 'ORIGIN')
    for flag in ('application_fix','FS15_accepted','physical_acceptance'):
        require(records[flag] is False, 'SCOPE_ESCALATION')
    require(type(records['case_count']) is int and records['case_count']==7, 'CASE_COUNT')
    require(type(records['case_records']) is list and len(records['case_records'])==7, 'CASE_COUNT')
    runtime_guard(records['runtime'])
    require([c.get('id') if type(c) is dict else None for c in records['case_records']]
            == oracle['acceptance']['required_case_order'], 'CASE_ORDER')
    total_reads=0
    total_events=0
    total_opens=0
    for raw, spec, sem in zip(records['case_records'],contract['cases'],oracle['cases']):
        keys(raw,contract['case_fields'],'CASE_FIELDS')
        cid=raw['id']
        require(raw['category']==sem['category'],'CATEGORY',cid)
        require(raw['complete'] is True,'INCOMPLETE',cid)
        require(type(raw['events']) is list and len(raw['events'])==len(spec['steps']), 'EVENT_COUNT',cid)
        require(type(raw['reads']) is list and type(raw['snapshots']) is list,'OBSERVATION_LISTS',cid)
        expected_read_steps=[(i,s) for i,s in enumerate(spec['steps']) if s['op']=='pread']
        expected_stat_steps=[(i,s) for i,s in enumerate(spec['steps']) if s['op']=='path_stat']
        require(len(raw['reads'])==len(expected_read_steps),'READ_COUNT',cid)
        require(len(raw['snapshots'])==len(expected_stat_steps),'SNAPSHOT_COUNT',cid)
        active={}
        for n,(event,step) in enumerate(zip(raw['events'],spec['steps'])):
            op=step['op']
            expected_keys=list(contract['event_fields'])
            if op in OPEN_OPS: expected_keys += contract['open_event_extra_fields']
            keys(event,expected_keys,'EVENT_FIELDS')
            require(type(event['index']) is int and event['index']==n,'EVENT_INDEX',cid)
            require(all(exact(event[k],step[k]) for k in ('op','role','leaf','phase','args')), 'EVENT_INTENT',cid)
            require(type(event['return']) is int and type(event['errno']) is int and event['errno']>=0,
                    'EVENT_INTEGER',cid)
            expected=step['expect']
            require(event['errno']==expected['errno'],'EVENT_ERRNO',cid)
            if expected['return']=='nonnegative_fd':
                require(event['return']>=0,'OPEN_RETURN',cid)
            else:
                require(event['return']==expected['return'],'EVENT_RETURN',cid)
            require(type(event['success']) is bool and event['success']==(event['errno']==0 and event['return']>=0),
                    'EVENT_SUCCESS',cid)
            role=event['role']
            if op in OPEN_OPS:
                require(role not in active,'HANDLE_LIFETIME',cid)
                require(event['return'] not in active.values(),'HANDLE_ACTIVE_ALIAS',cid)
                expected_flags=0
                for flag in contract['open_flag_policy'][op]: expected_flags |= DARWIN_FLAGS[flag]
                require(type(event['actual_flags']) is int and event['actual_flags']==expected_flags,'OPEN_FLAGS',cid)
                require(event['actual_inheritable'] is False,'OPEN_INHERITABLE',cid)
                require(type(event['actual_mode']) is int and event['actual_mode']==(384 if op=='create' else 0),
                        'OPEN_MODE',cid)
                active[role]=event['return']
                total_opens += 1
            elif op=='close':
                require(role in active,'HANDLE_LIFETIME',cid)
                del active[role]
            elif op=='path_stat':
                require('dir' in active,'HANDLE_LIFETIME',cid)
            else:
                require(role in active,'HANDLE_LIFETIME',cid)
                if op=='rename_excl':
                    require(event['args']['to_dir_role'] in active,'HANDLE_LIFETIME',cid)
        require(not active,'HANDLE_UNCLOSED',cid)
        identities={}
        for read,(event_index,step) in zip(raw['reads'],expected_read_steps):
            keys(read,contract['read_fields'],'READ_FIELDS')
            require(type(read['event_index']) is int and read['event_index']==event_index,'READ_BINDING',cid)
            require(exact(read['role'],step['role']) and exact(read['phase'],step['phase']), 'READ_BINDING',cid)
            require(type(read['count']) is int and read['count']==4096 and type(read['offset']) is int
                    and read['offset']==0,'READ_INTEGER',cid)
            encoded=read['hex']
            require(type(encoded) is str and len(encoded)==8192,'READ_ENCODING',cid)
            try: payload=bytes.fromhex(encoded)
            except ValueError: raise RecordRejected('READ_ENCODING',cid) from None
            require(payload.hex()==encoded,'READ_ENCODING',cid)
            require(type(read['sha256']) is str and read['sha256']==hashlib.sha256(payload).hexdigest(),
                    'READ_HASH',cid)
            require(payload==PAYLOADS[step['expect']['read_payload']],'READ_PAYLOAD',cid)
            label=step['expect']['read_label']
            identities[label]=validate_identity(read['identity'],records['runtime'],
                                                  0 if cid=='M07' and label=='held_after' else 1)
            total_reads+=1
        for snapshot,(event_index,step) in zip(raw['snapshots'],expected_stat_steps):
            keys(snapshot,contract['snapshot_fields'],'SNAPSHOT_FIELDS')
            require(type(snapshot['event_index']) is int and snapshot['event_index']==event_index
                    and all(exact(snapshot[k],step[k]) for k in ('role','phase','leaf')),'SNAPSHOT_BINDING',cid)
            require(snapshot['exists'] is False and type(snapshot['errno']) is int and snapshot['errno']==2,
                    'SNAPSHOT_RESULT',cid)
        for relation,left,right in spec['identity_relations']:
            observed_same=identities[left]==identities[right]
            require(observed_same == (relation=='same'),'IDENTITY_RELATION',cid+':'+left+':'+right)
        total_events+=len(raw['events'])
    native=records['origin']=='NATIVE_DARWIN_OWN_FILES'
    return {'schema':1,'status':'SCOPED_SEVEN_OBSERVATIONS_MATCH_NOT_APPLICATION_FIX',
            'record_origin':records['origin'],'matched_case_count':7,
            'synthetic_cases':0 if native else 7,'native_claimed_cases':7 if native else 0,
            'independent_origin_verification':False,'events_validated':total_events,
            'reads_validated':total_reads,'own_open_close_pairs':total_opens,
            'application_fix':False,'FS15_accepted':False,'physical_acceptance':False,
            'limit':'Schema consistency is not attestation; native claim requires separately reviewed exact workflow/job/artifact binding.'}
