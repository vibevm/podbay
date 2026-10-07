#ifndef PODBAY_R1_WARM_SHARED_H
#define PODBAY_R1_WARM_SHARED_H
/* Fixed disposable diagnostic protocol; no production authority type. */
#include "closed_origin_shared.h"

#define W_POLICY "guest-r1-warm-v1;closed-before-source;custodian-loss;held-fd;no-admission"
#define W_MAGIC 0x52315731u
#define W_EVENT_CAP 2048
#define W_SOURCE "/fixture/vault/state/db.sqlite"
enum w_mode { W_BROKER=1, W_OUTSIDE=2 };
enum w_phase { W_READY=1, W_OPENED=2, W_BEFORE=3, W_AFTER=4, W_SEALED=5, W_LAST=6, W_DONE=7 };
enum w_command_kind { W_OPEN=1, W_HOLD_BEFORE=2, W_HOLD_AFTER=3, W_CHECK_SEAL=4, W_HOLD_LAST=5, W_RUN_OUTSIDE=6 };
struct w_config {
    char nonce[33], fixture[37], source_hash[65], lineage[33];
    char policy_hash[65], init_hash[65], probe_hash[65];
};
struct w_context {
    uint32_t magic, mode;
    int32_t self_pid, parent_pid, target_pid, target_fd;
    uint64_t self_birth, device, inode, bytes;
    char nonce[33], boot[37], hash[65];
};
struct w_command {
    uint32_t magic, sequence, kind;
    int32_t target_pid;
    char nonce[33], boot[37];
};
struct w_message {
    uint32_t magic, sequence, phase, flags;
    int32_t pid, parent_pid, rc, error, data_fd, denials[8];
    uint64_t birth, device, inode;
    char nonce[33], boot[37];
};
struct w_notice {
    uint32_t magic, sequence;
    int32_t custodian_pid, broker_pid, uid;
    uint64_t custodian_birth, broker_birth, device, lock_inode;
    char nonce[33], boot[37];
};
static inline int w_uuid(const char *s){
    if(strlen(s)!=36)return 0;
    for(unsigned i=0;i<36;i++){
        if(i==8||i==13||i==18||i==23){if(s[i]!='-')return 0;}
        else if(!((s[i]>='0'&&s[i]<='9')||(s[i]>='a'&&s[i]<='f')))return 0;
    }
    return 1;
}
static inline int w_cmdline(char *text){
    char *save=NULL;int found=0;
    for(char *s=strtok_r(text," \t\r\n",&save);s;s=strtok_r(NULL," \t\r\n",&save)){
        if(strncmp(s,"r1.warm=",8))continue;
        if(strcmp(s,"r1.warm=1")||found++)return 0;
    }
    return found==1;
}
static inline int w_can_launch(unsigned started,unsigned lost){return !started&&!lost;}
static inline int w_command_matches(const struct w_command *c,const struct w_context *x,unsigned seq,unsigned kind){
    return c->magic==W_MAGIC&&c->sequence==seq&&c->kind==kind&&c->target_pid==x->self_pid&&
        !memcmp(c->nonce,x->nonce,33)&&!memcmp(c->boot,x->boot,37);
}
static inline int w_message_matches(const struct w_message *m,const struct w_context *x,unsigned seq,unsigned phase,unsigned flags,int parent){
    return m->magic==W_MAGIC&&m->sequence==seq&&m->phase==phase&&m->flags==flags&&
        m->pid==x->self_pid&&m->birth==x->self_birth&&m->parent_pid==parent&&
        m->device==x->device&&m->inode==x->inode&&!memcmp(m->nonce,x->nonce,33)&&!memcmp(m->boot,x->boot,37);
}
#endif
