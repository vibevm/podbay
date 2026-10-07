#ifndef PODBAY_R1_TWO_BOOT_CHECKPOINT_H
#define PODBAY_R1_TWO_BOOT_CHECKPOINT_H
/* Private fixed diagnostic record. Decoding it never restores prior authority. */
#include "closed_origin_shared.h"

#define R1_POLICY "guest-r1-two-boot-v1;closed-before-source;owner1000;fresh-lock;no-admission"
#define R1_RECORD_CAP 2048
#define R1_EVENT_CAP 2048
#define R1_MAGIC 0x52314232u
#define R1_SOURCE "/fixture/vault/state/db.sqlite"
enum r1_mode { R1_BROKER_WRITE=1, R1_BROKER_READ=2, R1_OUTSIDE=3 };
enum r1_phase { R1_READY=1, R1_OPENED=2, R1_DONE=3, R1_HELD=4 };
static inline const char *r1_gate_label(unsigned established) {
    return established?"CLOSED":"PRE_CLOSURE";
}
/* /proc/cmdline appends a newline. Parse the same bounded token stream on
   both boots; a duplicate, malformed or missing phase never selects a boot. */
static inline char r1_command_phase(char *cmdline) {
    char phase=0,*save=NULL;
    for(char *word=strtok_r(cmdline," \t\r\n",&save);word;word=strtok_r(NULL," \t\r\n",&save)){
        if(strncmp(word,"r1.phase=",9))continue;
        if(phase||strlen(word)!=10||(word[9]!='A'&&word[9]!='B'))return 0;
        phase=word[9];
    }
    return phase;
}
struct r1_context {
    uint32_t magic, mode;
    uint64_t device, inode, bytes;
    int32_t target_pid, target_fd;
    char nonce[33], boot[37], hash[65];
};
struct r1_message {
    uint32_t magic, phase, flags;
    int32_t pid, rc, error, data_fd;
    int32_t denials[8];
    uint64_t device, inode;
    char nonce[33], boot[37];
};
static inline int r1_message_matches(const struct r1_message *m,const char nonce[33],const char boot[37],
                                    int pid,unsigned phase,unsigned flags,uint64_t device,uint64_t inode){
    return m->magic==R1_MAGIC&&m->pid==pid&&m->phase==phase&&m->flags==flags&&
      m->device==device&&m->inode==inode&&!memcmp(m->nonce,nonce,33)&&!memcmp(m->boot,boot,37);
}
struct r1_checkpoint {
    char nonce[33], fixture[37], boot_a[37], source_hash[65], lineage[33];
    char policy_hash[65], init_hash[65], probe_hash[65];
    uint64_t device, root_inode, vault_inode, state_inode, source_inode, lock_inode, source_bytes;
    uint64_t custodian_birth, broker_pid, broker_birth, broker_fd;
};
static inline int r1_uuid(const char *s) {
    if(strlen(s)!=36)return 0;
    for(unsigned i=0;i<36;i++){
        if(i==8||i==13||i==18||i==23){if(s[i]!='-')return 0;}
        else if(!((s[i]>='0'&&s[i]<='9')||(s[i]>='a'&&s[i]<='f')))return 0;
    }
    return 1;
}
static inline int r1_valid_checkpoint(const struct r1_checkpoint *r) {
    if(!hex_text(r->nonce,32)||!r1_uuid(r->fixture)||!r1_uuid(r->boot_a)||!hex_text(r->source_hash,64)||
       !hex_text(r->lineage,32)||!hex_text(r->policy_hash,64)||!hex_text(r->init_hash,64)||!hex_text(r->probe_hash,64)||
       !r->device||!r->custodian_birth||r->broker_pid<=1||r->broker_pid>INT_MAX||!r->broker_birth||
       r->broker_fd<3||r->broker_fd>1048576||r->source_bytes<4096||r->source_bytes>ORIGIN_FILE_CAP)return 0;
    uint64_t ids[]={r->root_inode,r->vault_inode,r->state_inode,r->source_inode,r->lock_inode};
    for(unsigned i=0;i<5;i++){if(!ids[i])return 0;for(unsigned j=0;j<i;j++)if(ids[i]==ids[j])return 0;}
    return 1;
}
static inline size_t r1_encode(const struct r1_checkpoint *r,char out[R1_RECORD_CAP]) {
    if(!r1_valid_checkpoint(r))return 0;
    int n=snprintf(out,R1_RECORD_CAP,
      "PODBAY-R1-CLOSED-CHECKPOINT/1\nnonce=%s\nfixture=%s\nboot_a=%s\nsource_sha256=%s\nlineage=%s\npolicy_sha256=%s\ninit_sha256=%s\nprobe_sha256=%s\n"
      "device=%020llu\nroot_inode=%020llu\nvault_inode=%020llu\nstate_inode=%020llu\nsource_inode=%020llu\nlock_inode=%020llu\nsource_bytes=%020llu\n"
      "custodian_pid=1\ncustodian_birth=%020llu\nbroker_pid=%020llu\nbroker_birth=%020llu\nbroker_fd=%020llu\n"
      "source_uid=1000\nsource_gid=1000\nsource_mode=0600\nstate_mode=0700\nvault_uid=0\nvault_mode=0700\n"
      "state=CLOSED_DIAGNOSTIC\nstage=ABSENT\nsidecars=ABSENT\nadmission=UNIMPLEMENTED\n",
      r->nonce,r->fixture,r->boot_a,r->source_hash,r->lineage,r->policy_hash,r->init_hash,r->probe_hash,
      (unsigned long long)r->device,(unsigned long long)r->root_inode,(unsigned long long)r->vault_inode,
      (unsigned long long)r->state_inode,(unsigned long long)r->source_inode,(unsigned long long)r->lock_inode,
      (unsigned long long)r->source_bytes,(unsigned long long)r->custodian_birth,(unsigned long long)r->broker_pid,
      (unsigned long long)r->broker_birth,(unsigned long long)r->broker_fd);
    if(n<=0||n+73>=R1_RECORD_CAP)return 0;
    struct sha256_state s;char hash[65];sha_init(&s);sha_update(&s,out,(size_t)n);sha_finish(&s,hash);
    int tail=snprintf(out+n,R1_RECORD_CAP-(size_t)n,"sha256=%s\n",hash);
    return tail==72?(size_t)n+72:0;
}
struct r1_reader { const char *data; size_t size, at; };
static inline int r1_literal(struct r1_reader *r,const char *value) {
    size_t n=strlen(value);if(n>r->size-r->at||memcmp(r->data+r->at,value,n))return 0;r->at+=n;return 1;
}
static inline int r1_text(struct r1_reader *r,const char *key,char *out,size_t n) {
    if(!r1_literal(r,key)||n+1>r->size-r->at||r->data[r->at+n]!='\n')return 0;
    memcpy(out,r->data+r->at,n);out[n]=0;r->at+=n+1;return 1;
}
static inline int r1_number(struct r1_reader *r,const char *key,uint64_t *out) {
    char text[21];if(!r1_text(r,key,text,20))return 0;uint64_t value=0;
    for(unsigned i=0;i<20;i++){if(text[i]<'0'||text[i]>'9')return 0;unsigned d=(unsigned)(text[i]-'0');
        if(value>(UINT64_MAX-d)/10)return 0;
        value=value*10+d;}
    *out=value;return 1;
}
static inline int r1_decode(const char *data,size_t n,struct r1_checkpoint *out) {
    if(n==0||n>=R1_RECORD_CAP||memchr(data,0,n))return 0;
    struct r1_reader p={.data=data,.size=n};struct r1_checkpoint r={0};char hash[65];
    if(!r1_literal(&p,"PODBAY-R1-CLOSED-CHECKPOINT/1\n")||
       !r1_text(&p,"nonce=",r.nonce,32)||!r1_text(&p,"fixture=",r.fixture,36)||
       !r1_text(&p,"boot_a=",r.boot_a,36)||!r1_text(&p,"source_sha256=",r.source_hash,64)||
       !r1_text(&p,"lineage=",r.lineage,32)||!r1_text(&p,"policy_sha256=",r.policy_hash,64)||
       !r1_text(&p,"init_sha256=",r.init_hash,64)||!r1_text(&p,"probe_sha256=",r.probe_hash,64)||
       !r1_number(&p,"device=",&r.device)||!r1_number(&p,"root_inode=",&r.root_inode)||
       !r1_number(&p,"vault_inode=",&r.vault_inode)||!r1_number(&p,"state_inode=",&r.state_inode)||
       !r1_number(&p,"source_inode=",&r.source_inode)||!r1_number(&p,"lock_inode=",&r.lock_inode)||
       !r1_number(&p,"source_bytes=",&r.source_bytes)||!r1_literal(&p,"custodian_pid=1\n")||
       !r1_number(&p,"custodian_birth=",&r.custodian_birth)||!r1_number(&p,"broker_pid=",&r.broker_pid)||
       !r1_number(&p,"broker_birth=",&r.broker_birth)||!r1_number(&p,"broker_fd=",&r.broker_fd)||
       !r1_literal(&p,"source_uid=1000\nsource_gid=1000\nsource_mode=0600\nstate_mode=0700\nvault_uid=0\nvault_mode=0700\nstate=CLOSED_DIAGNOSTIC\nstage=ABSENT\nsidecars=ABSENT\nadmission=UNIMPLEMENTED\n")||
       !r1_text(&p,"sha256=",hash,64)||p.at!=n||!hex_text(hash,64)||!r1_valid_checkpoint(&r))return 0;
    char encoded[R1_RECORD_CAP];size_t expected=r1_encode(&r,encoded);
    if(expected!=n||memcmp(data,encoded,n))return 0;
    *out=r;return 1;
}
static inline int r1_same_pins(const struct r1_checkpoint *record,const struct r1_checkpoint *config,const char *current_boot) {
    return r1_uuid(current_boot)&&strcmp(record->boot_a,current_boot)&&
        !strcmp(record->nonce,config->nonce)&&!strcmp(record->fixture,config->fixture)&&
        !strcmp(record->source_hash,config->source_hash)&&!strcmp(record->lineage,config->lineage)&&
        !strcmp(record->policy_hash,config->policy_hash)&&!strcmp(record->init_hash,config->init_hash)&&
        !strcmp(record->probe_hash,config->probe_hash);
}
#endif
