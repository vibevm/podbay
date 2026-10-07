#!/usr/bin/env python3
"""Offline-only pinned disposable systemd VM builder. There is no VM launch switch."""
import argparse
import gzip
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys
sys.dont_write_bytecode = True
import offline
import run_closed_vm as closed
import run_closed_origin_vm as origin

BASE = Path('/home/olegchir/podbay-r1-systemd-vm-build')
HERE = Path(__file__).resolve().parent
SUCCESS = 'BOOTSTRAP_REFUSED_ISSUERS_BLOCKED_NO_PRODUCTION_ADMISSION'
OFFLINE = 'OFFLINE_SYSTEMD_CANDIDATE_UNBOOTED_NO_PRODUCTION_ADMISSION'
BOOTSTRAP = 'podbay-r1-closed-bootstrap.service'
CUSTODIAN = 'podbay-r1-custodian.service'
ISSUER = 'r1-issuer.service'
UUID = '10cc005e-0000-4000-8000-000000000024'
LINEAGE = '00000000000000000000000000000024'
PIN_NAMES = ('r1_systemd_runtime.json', 'init.r1_systemd.c', 'r1_systemd_observer.c',
             'build_r1_systemd_vm.py', 'offline.py', 'run_closed_vm.py', 'run_closed_origin_vm.py')
DIGEST = re.compile('[0-9a-f]{64}')
ANALYZE = '/usr/bin/systemd-analyze'
ANALYZE_SHA = '7056ccf8da593ccd9795085d45ef3af92fd27ca8765a3acd8efdc0fbf92fe6dc'
EXECUTOR = '/usr/lib/systemd/systemd-executor'
EXECUTOR_SHA = '94738f53492ff7f2921c9d1795b54013c577f776a6da94b0801bbd3b2619fd57'


def strict_json(data):
    return json.loads(data, object_pairs_hook=closed.strict_object,
                      parse_constant=lambda x: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def pinned(path, digest, limit=128*1024*1024):
    if not isinstance(digest,str) or not DIGEST.fullmatch(digest): raise ValueError('explicit SHA256 required')
    fd=offline.regular_fd(path)
    try:
        s=os.fstat(fd)
        if s.st_size>limit or s.st_mode & 0o022 or s.st_uid not in (0,os.getuid()) or s.st_nlink!=1:
            raise ValueError('unsafe/oversized pinned input: '+str(path))
        data=os.pread(fd,s.st_size,0)
        if len(data)!=s.st_size or offline.sha(data)!=digest: raise ValueError('pinned bytes mismatch: '+str(path))
        return data
    finally: os.close(fd)


def runtime_bytes(pins):
    if pins.get(EXECUTOR) != EXECUTOR_SHA:
        raise ValueError('required systemd executor pin missing or changed')
    result={}
    for guest,digest in pins.items():
        # Installed merged-/usr and versioned-library symlinks are resolved only
        # to root-owned non-writable regular targets; preserve exact guest names.
        resolved=Path(guest).resolve(strict=True)
        offline.trusted_tool(resolved)
        result[guest]=pinned(resolved,digest)
    result['/bin/busybox']=pinned(*offline.PINS['busybox'])
    offline.static_elf(result['/bin/busybox'])
    return result


def elf_info(data):
    if len(data)<64 or data[:7]!=b'\x7fELF\x02\x01\x01' or struct.unpack_from('<H',data,18)[0]!=62:
        raise ValueError('not bounded ELF64 x86_64')
    off=struct.unpack_from('<Q',data,32)[0];size,count=struct.unpack_from('<HH',data,54)
    if size!=56 or count>256 or off+size*count>len(data):raise ValueError('invalid ELF program table')
    loads=[];dynamic=None;interp=None
    for i in range(count):
        typ,flags,pos,addr,physical,filesz,memsz,align=struct.unpack_from('<IIQQQQQQ',data,off+i*size)
        if pos+filesz>len(data):raise ValueError('ELF segment outside file')
        if typ==1:loads.append((addr,pos,filesz))
        if typ==2:
            if dynamic is not None:raise ValueError('multiple dynamic segments')
            dynamic=(pos,filesz)
        if typ==3:
            if interp is not None or not data[pos:pos+filesz].endswith(b'\0'):raise ValueError('bad interpreter')
            interp=data[pos:pos+filesz-1].decode('ascii')
    needed=[];runpath=[]
    if dynamic:
        tags={};pos,length=dynamic
        if length%16:raise ValueError('bad dynamic table')
        for at in range(pos,pos+length,16):
            tag,value=struct.unpack_from('<QQ',data,at)
            if tag==0:break
            tags.setdefault(tag,[]).append(value)
        else:raise ValueError('unterminated dynamic table')
        if len(tags.get(5,[]))!=1 or len(tags.get(10,[]))!=1:raise ValueError('bad ELF strings')
        addr=tags[5][0];length=tags[10][0]
        matches=[p+addr-a for a,p,n in loads if a<=addr and addr+length<=a+n]
        if len(matches)!=1:raise ValueError('ELF string table not mapped')
        strings=data[matches[0]:matches[0]+length]
        def string(at):
            end=strings.find(b'\0',at)
            if at>=len(strings) or end<0:raise ValueError('invalid ELF dynamic string')
            return strings[at:end].decode('ascii')
        needed=[string(x) for x in tags.get(1,[])]
        runpath=[string(x) for t in (15,29) for x in tags.get(t,[])]
    return interp,needed,runpath


def verify_elf_closure(files):
    if '/usr/lib/systemd/systemd' in files and (
            EXECUTOR not in files or offline.sha(files[EXECUTOR]) != EXECUTOR_SHA):
        raise ValueError('required systemd executor bytes missing or changed')
    libs={Path(p).name:p for p in files if '/lib' in p}
    result={}
    for path,data in files.items():
        if not data.startswith(b'\x7fELF'):continue
        interpreter,needed,search=elf_info(data)
        if interpreter is not None and interpreter!='/lib64/ld-linux-x86-64.so.2':raise ValueError('foreign interpreter')
        if interpreter and interpreter not in files:raise ValueError('missing interpreter')
        for name in needed:
            if '/' in name or name not in libs:raise ValueError('missing ELF dependency '+name+' for '+path)
        if any(p not in ('/usr/lib/x86_64-linux-gnu/systemd',) for paths in search for p in paths.split(':')):
            raise ValueError('unreviewed ELF search path')
        result[path]={'interpreter':interpreter,'needed':needed,'search':search}
    return result


def parse_unit(data):
    if len(data)>16384:raise ValueError('oversized unit')
    section=None;result={}
    for line in data.decode('ascii').splitlines():
        line=line.strip()
        if not line or line.startswith('#'):continue
        if re.fullmatch(r'\[[A-Za-z]+\]',line):section=line[1:-1];continue
        if section is None or '=' not in line or '\\' in line or '\0' in line:raise ValueError('unsupported unit syntax')
        key,value=line.split('=',1);pair=(section,key)
        if pair in result:raise ValueError('duplicate unit key')
        result[pair]=value
    return result


def verify_units(units):
    parsed={name:parse_unit(data) for name,data in units.items()}
    graph={name:set() for name in units}
    for name,u in parsed.items():
        if name.endswith('.service') and u.get(('Unit','DefaultDependencies'),'yes')=='yes':
            graph[name].update(('basic.target','sysinit.target'))
            graph['shutdown.target'].add(name)
        for (section,key),value in u.items():
            if key.startswith(('Condition','Assert')) or key in ('OnFailure','ExecStop','ExecStopPost','ExecStartPre','ExecStartPost','EnvironmentFile'):
                raise ValueError('unreviewed skip/hook: '+name+':'+key)
            if key=='Restart' and value!='no':raise ValueError('restart forbidden')
            if section=='Unit' and key in ('After','Before','Requires','Wants'):
                for target in value.split():
                    if target not in graph:raise ValueError('unresolved unit '+target)
                    if key=='After':graph[name].add(target)
                    if key=='Before':graph[target].add(name)
    for name in (ISSUER,CUSTODIAN):
        u=parsed[name]
        if BOOTSTRAP not in u.get(('Unit','Requires'),'').split() or BOOTSTRAP not in u.get(('Unit','After'),'').split():
            raise ValueError('issuer lacks Requires+After')
    for name,role in ((BOOTSTRAP,'bootstrap'),(CUSTODIAN,'custodian')):
        u=parsed[name]
        expected='/usr/local/libexec/podbay-r1-linux '+role+' --manifest /etc/podbay/r1-install-manifest.json'
        if u.get(('Service','ExecStart'))!=expected or u.get(('Service','Restart'))!='no' or (name==BOOTSTRAP and u.get(('Unit','DefaultDependencies'))!='no'):
            raise ValueError('unexpected staged enforcer unit command/dependencies')
    active=set();done=set()
    def visit(name):
        if name in active:raise ValueError('unit ordering cycle')
        if name in done:return
        active.add(name)
        for dep in graph[name]:visit(dep)
        active.remove(name);done.add(name)
    for name in graph:visit(name)
    return parsed


def fixed_units(staged, issuer_dropin=None):
    units=dict(staged)
    def put(name,body):units[name]=body.encode()
    issuer='[Unit]\nDefaultDependencies=no\n[Service]\nType=oneshot\nUser=1000\nGroup=1000\nExecStart=/bin/busybox touch /tmp/r1-issuer-ran\nRestart=no\n'
    if issuer_dropin is None:issuer_dropin=('[Unit]\nRequires='+BOOTSTRAP+'\nAfter='+BOOTSTRAP+'\n').encode()
    if parse_unit(issuer_dropin)!={('Unit','Requires'):BOOTSTRAP,('Unit','After'):BOOTSTRAP}:
        raise ValueError('issuer drop-in differs from fixed Requires+After gate')
    put(ISSUER,issuer+issuer_dropin.decode())
    put('r1-observer.service','[Unit]\nDefaultDependencies=no\nAfter='+BOOTSTRAP+' '+CUSTODIAN+' '+ISSUER+'\n[Service]\nType=oneshot\nExecStart=/usr/local/libexec/r1-observer\nTimeoutStartSec=50s\nRestart=no\nStandardOutput=tty\nStandardError=tty\nTTYPath=/dev/console\n')
    put('r1-test.target','[Unit]\nDefaultDependencies=no\nWants='+BOOTSTRAP+' '+CUSTODIAN+' '+ISSUER+' r1-observer.service\nAfter=r1-observer.service\nAllowIsolate=yes\n')
    put('local-fs.target','[Unit]\nDefaultDependencies=no\n')
    put('sysinit.target','[Unit]\nDefaultDependencies=no\nAfter=local-fs.target\n')
    put('basic.target','[Unit]\nDefaultDependencies=no\nRequires=sysinit.target\nAfter=sysinit.target\n')
    for name in ('shutdown.target','umount.target','final.target','system.slice'):
        put(name,'[Unit]\nDefaultDependencies=no\n')
    put('poweroff.target','[Unit]\nDefaultDependencies=no\nRequires=systemd-poweroff.service\nAfter=systemd-poweroff.service\n')
    put('systemd-poweroff.service','[Unit]\nDefaultDependencies=no\nRequires=shutdown.target umount.target final.target\nAfter=shutdown.target umount.target final.target\n[Service]\nType=oneshot\nExecStart=/usr/bin/systemctl --force poweroff\nRestart=no\n')
    # This root-in-archive fixture mounts /dev/vda before systemd. It deliberately
    # does not claim a vendor udev/.device boot proof or a host issuer inventory.
    verify_units(units)
    return units


def verify_systemd(output, entries):
    """Extract our generated regular files privately, never execute them."""
    offline.trusted_tool(ANALYZE);pinned(ANALYZE,ANALYZE_SHA)
    root=output.out/'verify-root'
    os.mkdir(root,0o700)
    for name,mode,data,major,minor in entries:
        path=root/name
        if stat.S_ISDIR(mode):
            path.mkdir(mode=0o700,parents=True,exist_ok=True)
        elif stat.S_ISREG(mode):
            path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o700 if mode&0o111 else 0o600)
            try:closed.write_all(fd,data)
            finally:os.close(fd)
        elif not (name=='dev/console' and stat.S_ISCHR(mode)):
            raise ValueError('unreviewed extraction type')
    args=[ANALYZE,'--root='+str(root),'--generators=no','--man=no','verify','r1-test.target','poweroff.target']
    output.check()
    r=subprocess.run(args,capture_output=True,timeout=30,env={'PATH':'/usr/bin:/bin','LC_ALL':'C','SYSTEMD_LOG_COLOR':'0'})
    output.check();output.write('systemd-verify.log',r.stdout+r.stderr)
    if r.returncode or r.stdout or r.stderr:raise ValueError('systemd unit verification emitted diagnostics; inspect retained log')
    return {'argv':args,'exit':r.returncode,'sha256':ANALYZE_SHA,'native_ordering_proved':False}


MAX_EVENT = 2048


def parse_events(raw,pins):
    """Only the dedicated ttyS1 channel can carry the single observer event."""
    if (not isinstance(raw,bytes) or not 0<len(raw)<MAX_EVENT or raw.count(b'\n')!=1
            or not raw.endswith(b'\n') or b'\r' in raw or b'\0' in raw or b'\x1b' in raw
            or not raw.startswith(b'R1_SYSTEMD ')):
        raise ValueError('invalid dedicated observer channel')
    e=strict_json(raw[11:-1].decode('utf-8','strict'))
    expected=dict(schema=1,event=SUCCESS,pid1=1,bootstrap_exit=2,custodian_exit=2,issuer_starts=0,outside_denials=4,enforcer_gate='UNESTABLISHED',admission='UNAVAILABLE',**{k:pins[k] for k in ('enforcer_sha256','manifest_sha256','systemd_sha256','archive_generation')})
    if not isinstance(e,dict) or set(e)!=set(expected)|{'boot_id','observer_pid'} or any(e[k]!=v or type(e[k]) is not type(v) for k,v in expected.items()):raise ValueError('foreign or authority-claim event')
    if type(e['observer_pid']) is not int or e['observer_pid']<=1 or not isinstance(e['boot_id'],str) or not origin.BOOT_ID.fullmatch(e['boot_id']):raise ValueError('bad actual boot/observer identity')
    return e



def verify_console(raw):
    """Keep raw ttyS0 diagnostics; strip terminal controls only for fatal checks."""
    if not isinstance(raw,bytes) or len(raw)>closed.MAX_SERIAL or not raw.endswith(b'\n') or b'\0' in raw:
        raise ValueError('invalid diagnostic console capture')
    text=raw.decode('utf-8','strict')
    if 'R1_SYSTEMD' in text:raise ValueError('observer event leaked into console')
    fatal=r'kernel panic|not syncing|oops:|BUG:|segmentation fault|R1_.*FAILED|ordering cycle|Failed to execute|Failed to mount|Failed to allocate manager|Freezing execution'
    if re.search(fatal,text,re.I):raise ValueError('fatal raw diagnostic console')
    text=text.replace('\r','')
    if re.search(fatal,text,re.I):raise ValueError('fatal CR-normalized diagnostic console')
    # The observed console uses non-nested CSI/OSC/DCS only. Reject nested
    # escapes before any destructive removal; payloads cannot conceal tokens
    # that a subsequent normalization stage would reconstruct and discard.
    cursor=0
    while True:
        start=text.find('\x1b',cursor)
        if start<0:break
        kind=text[start+1:start+2]
        if kind=='[':
            control=re.match(r'\x1b\[[0-?]*[ -/]*[@-~]',text[start:])
            if control is None:raise ValueError('malformed CSI diagnostic control')
            cursor=start+len(control.group())
        elif kind in (']','P'):
            cursor=start+2
            while cursor<len(text):
                if kind==']' and text[cursor]=='\x07':cursor+=1;break
                if text[cursor]=='\x1b':
                    if text[cursor:cursor+2]!='\x1b\\':
                        raise ValueError('nested diagnostic escape control')
                    cursor+=2;break
                cursor+=1
            else:raise ValueError('unterminated diagnostic string control')
        else:raise ValueError('unrecognized diagnostic terminal control')
    # Bounded CSI, OSC and DCS sequences observed from systemd's console setup.
    # This normalization is never applied to structured observer bytes.
    text=re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]','',text)
    # CSI may split a fatal token inside an OSC/DCS payload. Inspect that
    # joined text before discarding payloads, not only before/after all strips.
    if re.search(fatal,text,re.I):raise ValueError('fatal CSI-normalized diagnostic console')
    text=re.sub(r'\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)','',text)
    if re.search(fatal,text,re.I):raise ValueError('fatal OSC-normalized diagnostic console')
    text=re.sub(r'\x1bP[^\x1b]*(?:\x1b\\)','',text)
    if re.search(fatal,text,re.I):raise ValueError('fatal DCS-normalized diagnostic console')
    if '\x1b' in text:raise ValueError('unrecognized diagnostic terminal control')
    if re.search(fatal,text,re.I):
        raise ValueError('fatal diagnostic console')
    lines=[x for x in text.splitlines() if x.strip()]
    shutdown=[i for i,x in enumerate(lines) if re.fullmatch(r'(?:\[\s*\d+\.\d+\]\s*)?reboot: Power down',x)]
    if shutdown!=[len(lines)-1]:raise ValueError('missing/duplicate/nonfinal console shutdown')
    return True


def native_receipt(events,pins,exit_code,exact_reaped,pidfd_verified,stderr=b'',console=None):
    if type(exit_code) is not int or exit_code!=0 or exact_reaped is not True or pidfd_verified is not True or stderr:
        raise ValueError('native lifecycle/stderr failure')
    verify_console(console)
    return parse_events(events,pins)


def planned_qemu(kernel,archive,disk,event_path='EVENT_PIPE_FD_REQUIRED'):
    args=closed.qemu_argv(kernel,archive,disk)
    args[args.index('-append')+1]+=' quiet loglevel=4 systemd.show_status=false systemd.log_level=warning'
    args+=['-chardev','file,id=r1events,path='+str(event_path),'-serial','chardev:r1events']
    return args


def archive(files):
    entries={}
    for path,data in files.items():
        if not path.startswith('/') or '..' in Path(path).parts:raise ValueError('unsafe archive path')
        name=path[1:]
        mode=0o755 if data.startswith(b'\x7fELF') else 0o600
        entries[name]=(name,stat.S_IFREG|mode,data,0,0)
        for parent in Path(name).parents:
            if str(parent)!='.':entries.setdefault(str(parent),(str(parent),stat.S_IFDIR|0o755,b'',0,0))
    for name in ('dev','proc','sys','run','tmp','fixture'):
        entries[name]=(name,stat.S_IFDIR|(0o700 if name=='fixture' else 0o1777 if name=='tmp' else 0o755),b'',0,0)
    entries['dev/console']=('dev/console',stat.S_IFCHR|0o600,b'',5,1)
    result=sorted(entries.values())
    return gzip.compress(offline.newc(result),mtime=0),result


def disk_build(output,seed):
    for key in ('mke2fs','debugfs'):
        path,digest=offline.PINS[key];offline.trusted_tool(path);pinned(path,digest)
    output.write('source24.sqlite',seed);output.write('manager.lock',b'')
    output.write('fixture.raw',b'');disk=output.pins[output.out/'fixture.raw'];os.ftruncate(disk,offline.SIZE)
    output.write('mke2fs.conf',b'[defaults]\nbase_features = sparse_super,large_file,filetype,extent\nblocksize = 4096\ninode_size = 256\n[fs_types]\next4 = {\nfeatures = extent\n}\n')
    env={'PATH':'/usr/bin:/bin','LC_ALL':'C','TZ':'UTC','E2FSPROGS_FAKE_TIME':str(offline.EPOCH),'SOURCE_DATE_EPOCH':str(offline.EPOCH),'MKE2FS_CONFIG':str(output.out/'mke2fs.conf')}
    def call(args,tag,binary=False):
        output.check();r=subprocess.run(args,capture_output=True,timeout=60,env=env,pass_fds=(disk,));output.check()
        output.write(tag+'.log',r.stdout+r.stderr)
        if r.returncode or re.search(rb'File not found|Filesystem not open|Usage:|while |Command not found|Could not|Error|not a directory',r.stderr if binary else r.stdout+r.stderr,re.I):raise ValueError('disk tool failed '+tag)
        return r.stdout
    call([offline.PINS['mke2fs'][0],'-q','-t','ext4','-b','4096','-I','256','-N','2048','-m','0','-U',UUID,'-O','none,extent,filetype,sparse_super,large_file','-E','lazy_itable_init=0,hash_seed='+UUID,f'/proc/self/fd/{disk}'],'mkfs')
    commands=f'rmdir /lost+found\nmkdir /vault\nmkdir /vault/state\nwrite {output.out}/source24.sqlite /vault/state/db.sqlite\nwrite {output.out}/manager.lock /vault/manager.lock\n'
    paths={'/':(0,'040700'),'/vault':(0,'040700'),'/vault/state':(1000,'040700'),'/vault/state/db.sqlite':(1000,'0100600'),'/vault/manager.lock':(0,'0100600')}
    for path,(uid,mode) in paths.items():
        for key,value in (('uid',uid),('gid',uid),('mode',mode),('atime',offline.EPOCH),('ctime',offline.EPOCH),('mtime',offline.EPOCH),('crtime',offline.EPOCH)):
            commands+=f'set_inode_field {path} {key} {value}\n'
    output.write('populate.debugfs',commands.encode())
    call([offline.PINS['debugfs'][0],'-w','-f',str(output.out/'populate.debugfs'),f'/proc/self/fd/{disk}'],'populate')
    output.write('inspect.debugfs',(''.join('stat '+p+'\n' for p in paths)+'ls -p /\nls -p /vault\nls -p /vault/state\n').encode())
    call([offline.PINS['debugfs'][0],'-f',str(output.out/'inspect.debugfs'),f'/proc/self/fd/{disk}'],'inspect')
    data=call([offline.PINS['debugfs'][0],'-R','cat /vault/state/db.sqlite',f'/proc/self/fd/{disk}'],'readback',binary=True)
    if data!=seed:raise ValueError('disk source mismatch')
    return paths


def prepare(name,enforcer,enforcer_sha,stage,manifest_sha,unit_pins,plan_sha):
    if os.getuid()==0 or os.geteuid()==0:raise ValueError('ordinary UID required')
    if not re.fullmatch(r'systemd-[a-z0-9][a-z0-9-]{0,22}',name):raise ValueError('fresh systemd- name required')
    # All arguments describe bytes; no caller-supplied command can be executed.
    enforcer_data=pinned(enforcer,enforcer_sha)
    stage=Path(stage)
    plan_bytes=pinned(stage/'plan.json',plan_sha,256*1024)
    plan=strict_json(plan_bytes)
    if plan.get('schema')!='podbay.r1.install-plan/1' or plan.get('deployment_blocked') is not True or plan.get('activation_links_created') is not False:
        raise ValueError('stage is not an unavailable offline plan')
    manifest=pinned(stage/'rootfs/etc/podbay/r1-install-manifest.json',manifest_sha,65536)
    if strict_json(manifest)!={'schema':'podbay.r1.install-manifest/1','availability':'UNAVAILABLE','deployment_blocked':True,'reason':'COLD_BOOT_PROVENANCE_UNAVAILABLE'}:
        raise ValueError('wrong unavailable install manifest')
    staged={n:pinned(stage/'rootfs/etc/systemd/system'/n,unit_pins[n],16384) for n in (BOOTSTRAP,CUSTODIAN)}
    issuer_dropin=pinned(stage/'rootfs/etc/systemd/system'/ (ISSUER+'.d')/'50-podbay-r1-closed.conf',unit_pins['issuer'],16384)
    units=fixed_units(staged,issuer_dropin)
    issuer_base=units[ISSUER][:-len(issuer_dropin)]
    inventory=plan.get('issuer_inventory',{})
    if inventory.get('scope')!='DISPOSABLE_SYSTEMD_IMAGE_ONLY' or inventory.get('independently_verified') is not False or inventory.get('issuers')!=[{'declared_unit_sha256':offline.sha(issuer_base),'inventory_verified':False,'manager':'system','uid':1000,'unit':ISSUER}]:
        raise ValueError('stage issuer inventory differs from exact fixture')
    wanted={'/etc/podbay/r1-install-manifest.json':manifest_sha,'/usr/local/libexec/podbay-r1-linux':enforcer_sha,**{'/etc/systemd/system/'+n:h for n,h in unit_pins.items() if n!='issuer'},'/etc/systemd/system/'+ISSUER+'.d/50-podbay-r1-closed.conf':unit_pins['issuer']}
    records=plan.get('files',[])
    if len(records)!=len(wanted) or {x.get('destination'):x.get('sha256') for x in records}!=wanted:
        raise ValueError('stage artifact plan/pins differ')
    source={n:(HERE/n).read_bytes() for n in PIN_NAMES}
    runtime_pins=strict_json(source['r1_systemd_runtime.json']);files=runtime_bytes(runtime_pins)
    files['/usr/local/libexec/podbay-r1-linux']=enforcer_data
    closure=verify_elf_closure(files)
    schema=origin.SCHEMA.read_text();seed=origin.seed_database(schema,LINEAGE)
    subject=plan.get('subject',{})
    expected_subject={'schema_sha256':offline.sha(schema.encode()),'source_bytes':len(seed),'source_lineage':LINEAGE,'source_relative_path':'state/db.sqlite','source_sha256':offline.sha(seed),'vault_path':'/fixture/vault'}
    if any(subject.get(k)!=v for k,v in expected_subject.items()):raise ValueError('stage source subject differs from generated specimen')
    expected={'enforcer_sha256':enforcer_sha,'manifest_sha256':manifest_sha,'systemd_sha256':runtime_pins['/usr/lib/systemd/systemd']}
    generation=offline.sha(json.dumps({'pins':expected,'plan':plan_sha,'units':{n:offline.sha(d) for n,d in units.items()},'sources':{n:offline.sha(d) for n,d in source.items()},'seed':offline.sha(seed)},sort_keys=True).encode())
    expected['archive_generation']=generation
    with offline.TrustedOutput(BASE,create=True) as out:
        out.create_dir(name)
        for n,data in source.items():out.write(n,data)
        out.write('install-plan.json',plan_bytes)
        header=''.join('#define '+k+' "'+v+'"\n' for k,v in (('ENFORCER_SHA',enforcer_sha),('MANIFEST_SHA',manifest_sha),('SYSTEMD_SHA',expected['systemd_sha256']),('GENERATION',generation)))
        out.write('r1_systemd_pins.h',header.encode())
        offline.trusted_tool(origin.GCC);pinned(origin.GCC,origin.GCC_SHA256)
        for source_name,target in (('init.r1_systemd.c','init'),('r1_systemd_observer.c','observer')):
            out.write(target,b'')
            cmd=[str(origin.GCC),'-std=c11','-static','-Os','-Wall','-Wextra','-Werror','-ffile-prefix-map='+str(out.out)+'=.','-Wl,--build-id=none',str(out.out/source_name),'-o',str(out.out/target)]
            r=subprocess.run(cmd,capture_output=True,timeout=60,env={'PATH':'/usr/bin:/bin','LC_ALL':'C','TZ':'UTC','SOURCE_DATE_EPOCH':str(offline.EPOCH)})
            os.fchmod(out.pins[out.out/target],0o600);out.check();out.write(target+'.compile.log',r.stdout+r.stderr)
            if r.returncode:raise ValueError('static compile failed '+target)
            offline.static_elf(out.read(target))
        files['/init']=out.read('init');files['/usr/local/libexec/r1-observer']=out.read('observer')
        files['/etc/podbay/r1-install-manifest.json']=manifest
        for n,data in units.items():files['/etc/systemd/system/'+n]=data
        # Preserve the exact staged drop-in rather than merely regenerating an
        # equivalent gate. The merged form above is used only for graph checks.
        files['/etc/systemd/system/'+ISSUER]=units[ISSUER][:-len(issuer_dropin)]
        files['/etc/systemd/system/'+ISSUER+'.d/50-podbay-r1-closed.conf']=issuer_dropin
        # Output redirection is fixture-only instrumentation, exact staged
        # production ExecStart and Requires/After bytes remain unchanged.
        files['/etc/systemd/system/'+BOOTSTRAP+'.d/90-fixture-output.conf']=b'[Service]\nStandardOutput=file:/run/r1-bootstrap.out\nStandardError=file:/run/r1-bootstrap.err\n'
        files['/etc/passwd']=b'root:x:0:0:root:/:/bin/false\nfixture:x:1000:1000:fixture:/:/bin/false\n'
        files['/etc/group']=b'root:x:0:\nfixture:x:1000:\n'
        files['/etc/machine-id']=b''
        files['/etc/os-release']=b'ID=ubuntu\nVERSION_ID="26.04"\nPRETTY_NAME="Pinned disposable systemd fixture"\n'
        files['/etc/r1-artifacts.sha256']=(''.join(offline.sha(files[p])+'  '+p+'\n' for p in ('/usr/local/libexec/podbay-r1-linux','/usr/lib/systemd/systemd','/etc/podbay/r1-install-manifest.json'))+expected['systemd_sha256']+'  /proc/1/exe\n'+offline.sha(seed)+'  /fixture/vault/state/db.sqlite\n').encode()
        archive_bytes,entries=archive(files)
        syntax=verify_systemd(out,entries)
        out.write('initramfs.cpio.gz',archive_bytes)
        out.write('archive-manifest.json',(json.dumps([{'path':n,'mode':m,'sha256':offline.sha(d),'bytes':len(d)} for n,m,d,a,b in entries],indent=2)+'\n').encode())
        with offline.TrustedOutput(origin.INPUT) as inputs:
            for n,h in (('vmlinuz',offline.KERNEL[2]),('kernel.config',offline.CONFIG_HASH),('modules.builtin',offline.BUILTIN_HASH)):
                fd=closed.attach(inputs,n,h);out.write(n,os.pread(fd,os.fstat(fd).st_size,0))
        cfg=out.read('kernel.config').decode().splitlines()
        if any('CONFIG_'+x+'=y' not in cfg for x in (*offline.REQUIRED_CONFIG,'UNIX','CGROUPS','CGROUP_PIDS','EPOLL','INOTIFY_USER','FHANDLE','BINFMT_ELF','SERIAL_8250','SERIAL_CORE')):raise ValueError('missing kernel/systemd builtin')
        if any(x not in out.read('modules.builtin').decode().splitlines() for x in offline.REQUIRED_BUILTIN):raise ValueError('missing storage builtin')
        disk_build(out,seed);origin.verify_seed(out.out/'source24.sqlite',schema,LINEAGE)
        report=dict(expected,schema=1,status=OFFLINE,boot_executed=False,native_execution_supported=False,install_plan_sha256=plan_sha,tool_pins={**offline.PINS,'compiler':(str(origin.GCC),origin.GCC_SHA256)},systemd_syntax=syntax,output=str(out.out),runtime_pins=runtime_pins,elf_closure=closure,unit_pins=unit_pins,source_pins={n:offline.sha(d) for n,d in source.items()},builder_sha256=offline.sha(Path(__file__).read_bytes()),schema_sha256=offline.sha(schema.encode()),source_sha256=offline.sha(seed),fixture_uuid=UUID,lineage=LINEAGE,artifacts={n:offline.sha(out.read(n)) for n in ('vmlinuz','initramfs.cpio.gz','fixture.raw')},qemu_plan=planned_qemu('vmlinuz','initramfs.cpio.gz','fixture.raw'),limits=['Unbooted; no actual systemd ordering or native refusal observed','Offline closure/graph are not native acceptance','Ordinary invoking UID/root/compiler toolchain trusted; compiler driver pinned only','Fixture issuer graph only, no host production inventory or admission'])
        for fd in out.pins.values():
            if stat.S_ISREG(os.fstat(fd).st_mode):os.fsync(fd)
        closed.durable_receipt(out,'plan.json',report)
        return report


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('name','enforcer','enforcer-sha256','stage','manifest-sha256','bootstrap-sha256','custodian-sha256','issuer-sha256','plan-sha256'):p.add_argument('--'+name,required=True)
    a=p.parse_args()
    try:
        report=prepare(a.name,a.enforcer,a.enforcer_sha256,a.stage,a.manifest_sha256,{BOOTSTRAP:a.bootstrap_sha256,CUSTODIAN:a.custodian_sha256,'issuer':a.issuer_sha256},a.plan_sha256)
        print(json.dumps(report,sort_keys=True));return 0
    except (ValueError,OSError,subprocess.SubprocessError) as e:
        print(json.dumps({'status':'OFFLINE_REFUSED_RETAIN_ARTIFACTS','boot_executed':False,'error':str(e)}),file=sys.stderr);return 2
if __name__=='__main__':sys.exit(main())
