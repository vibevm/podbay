#ifndef R1_PRODUCER_WATCH_H
#define R1_PRODUCER_WATCH_H
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/inotify.h>
#include <unistd.h>
#define WATCH_MASK (IN_OPEN|IN_ACCESS|IN_MODIFY|IN_ATTRIB|IN_CLOSE_WRITE|IN_MOVE_SELF|IN_DELETE_SELF|IN_UNMOUNT)
struct watches { int fd,source,lock; };
static int watch_decode(struct watches w,const unsigned char *data,size_t count,uint32_t flags[2]) {
    size_t at=0;
    while(at<count) {
        struct inotify_event e;
        if(count-at<sizeof e){errno=EPROTO;return -1;}
        memcpy(&e,data+at,sizeof e);
        if(e.len || !e.mask){errno=EPROTO;return -1;}
        if(e.mask&IN_Q_OVERFLOW){errno=EOVERFLOW;return -1;}
        if(e.mask&~WATCH_MASK){errno=EPROTO;return -1;}
        if(e.mask&(IN_IGNORED|IN_MOVE_SELF|IN_DELETE_SELF|IN_UNMOUNT)){errno=ESTALE;return -1;}
        if(e.wd==w.source)flags[0]|=e.mask;
        else if(e.wd==w.lock)flags[1]|=e.mask;
        else {errno=EPROTO;return -1;}
        at+=sizeof e;
    }
    return 0;
}
static int watch_drain(struct watches w,uint32_t flags[2]) {
    unsigned char data[4096];
    for(;;) {
        ssize_t n=read(w.fd,data,sizeof data);
        if(n<0 && errno==EAGAIN)return 0;
        if(n<0 && errno==EINTR)continue;
        if(n<=0)return -1;
        if(watch_decode(w,data,(size_t)n,flags))return -1;
    }
}
static struct watches watch_start(const char *source,const char *lock) {
    struct watches w={-1,-1,-1};
    w.fd=inotify_init1(IN_NONBLOCK|IN_CLOEXEC);
    if(w.fd<0)return w;
    w.source=inotify_add_watch(w.fd,source,WATCH_MASK);
    w.lock=inotify_add_watch(w.fd,lock,WATCH_MASK);
    if(w.source<0||w.lock<0||w.source==w.lock){close(w.fd);w.fd=-1;}
    return w;
}
#endif
