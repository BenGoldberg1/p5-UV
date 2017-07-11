#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#define NEED_newRV_noinc
#define NEED_newCONSTSUB
#define NEED_sv_2pv_flags
#include "ppport.h"

#define MATH_INT64_NATIVE_IF_AVAILABLE
#include "perl_math_int64.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <uv.h>

#define uv_loop(h)      INT2PTR (uv_loop_t *, SvIVX (((uv_handle_t *)(h))->loop))
#define uv_data(h)      ((handle_data_t *)((uv_handle_t *)(h))->data)
#define uv_user_data(h) uv_data(h)->user_data;

struct UVAPI {
    uv_loop_t *default_loop;
};

/* data to store with a HANDLE */
typedef struct handle_data_s {
    SV *self;
    SV *loop_sv;
    HV *stash;
    SV *user_data;
    /* callbacks available */
    SV *alloc_cb;
    SV *close_cb;
    SV *timer_cb;
} handle_data_t;

static struct UVAPI uvapi;
static SV *default_loop_sv;
static HV *stash_loop;

/* handle stashes */
static HV *handle_type2stash[UV_HANDLE_TYPE_MAX] = {NULL};

/* request stashes */
static HV *request_type2stash[UV_REQ_TYPE_MAX] = {NULL};

static SV * s_get_cv (SV *cb_sv)
{
    dTHX;
    HV *st;
    GV *gvp;

    return (SV *)sv_2cv(cb_sv, &st, &gvp, 0);
}

static SV * s_get_cv_croak (SV *cb_sv)
{
    SV *cv = s_get_cv(cb_sv);

    if (!cv) {
        dTHX;
        croak("%s: callback must be a CODE reference or another callable object", SvPV_nolen(cb_sv));
    }

    return cv;
}

/* Handle callback function definitions */
static void handle_alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf);
static void handle_close_cb(uv_handle_t* handle);
static void handle_timer_cb(uv_timer_t* handle);

/* loop functions */
static void loop_default_init()
{
    if (!default_loop_sv) {
        uvapi.default_loop = uv_default_loop();
        if (!uvapi.default_loop) {
            croak("Error getting a new default loop");
        }
        default_loop_sv = sv_bless(
            newRV_noinc(newSViv(PTR2IV(uvapi.default_loop))),
            stash_loop
        );
    }
}

static uv_loop_t * loop_new()
{
    uv_loop_t *loop;
    int ret;
    Newx(loop, 1, uv_loop_t);
    if (NULL == loop) {
        croak("Unable to allocate space for a new loop");
    }
    ret = uv_loop_init(loop);
    if (0 != ret) {
        Safefree(loop);
        croak("Error initializing loop (%i): %s", ret, uv_strerror(ret));
    }
    return loop;
}

/* handle functions */
static SV * handle_bless(uv_handle_t *h)
{
    SV *rv;
    handle_data_t *data_ptr = h->data;

    if (SvOBJECT(data_ptr->self)) {
        rv = newRV_inc(data_ptr->self);
    }
    else {
        rv = newRV_noinc(data_ptr->self);
        sv_bless(rv, data_ptr->stash);
        SvREADONLY_on(data_ptr->self);
    }
    return rv;
}

static void handle_data_destroy(handle_data_t *data_ptr)
{
    if (NULL == data_ptr) return;

    /* cleanup self, loop_sv, user_data, and stash */
    if (NULL != data_ptr->self) {
        data_ptr->self = NULL;
    }
    if (NULL != data_ptr->stash) {
        SvREFCNT_dec(data_ptr->stash);
        data_ptr->stash = NULL;
    }

    /* cleanup any callback references */
    if (NULL != data_ptr->alloc_cb) {
        SvREFCNT_dec(data_ptr->alloc_cb);
        data_ptr->alloc_cb = NULL;
    }
    if (NULL != data_ptr->close_cb) {
        SvREFCNT_dec(data_ptr->close_cb);
        data_ptr->close_cb = NULL;
    }
    if (NULL != data_ptr->timer_cb) {
        SvREFCNT_dec(data_ptr->timer_cb);
        data_ptr->timer_cb = NULL;
    }
    Safefree(data_ptr);
    data_ptr = NULL;
}

static handle_data_t* handle_data_new(const uv_handle_type type)
{
    handle_data_t *data_ptr;
	
	if( type < 0 || type >= UV_HANDLE_TYPE_MAX || !handle_type2stash[type] ) {
        croak("Invalid Handle type supplied");
	}
	
	data_ptr = (handle_data_t *)malloc(sizeof(handle_data_t));
    if (NULL == data_ptr) {
        croak("Cannot allocate space for handle data.");
    }

    /* set the stash location */
    data_ptr->stash = handle_type2stash[type];

    /* setup the loop_sv slot */
    data_ptr->loop_sv = NULL;

    /* setup the callback slots */
    data_ptr->alloc_cb = NULL;
    data_ptr->close_cb = NULL;
    data_ptr->timer_cb = NULL;
    return data_ptr;
}

static void handle_destroy(uv_handle_t *handle)
{
    if (NULL == handle) return;
    if (0 == uv_is_closing(handle) && 0 == uv_is_active(handle)) {
        uv_close(handle, handle_close_cb);
        handle_data_destroy(uv_data(handle));
        /*Safefree(handle);*/
    }
}

static uv_handle_t* handle_new(const uv_handle_type type)
{
    uv_handle_t *handle;
    SV *self;
    handle_data_t *data_ptr = handle_data_new(type);
    size_t size = uv_handle_size(type);

    self = NEWSV (0, size);
    SvPOK_only(self);
    SvCUR_set(self, size);
    handle = (uv_handle_t *) SvPVX(self);
    if (NULL == handle) {
        Safefree(self);
        croak("Cannot allocate space for a new uv_handle_t");
    }

    /* add some data to our new handle */
    data_ptr->self = self;
    handle->data = (void *)data_ptr;
    return handle;
}

static void handle_on(uv_handle_t *handle, const char *name, SV *cb)
{
    SV *callback = NULL;
    handle_data_t *data_ptr;

    if (NULL == handle) return;
    data_ptr = uv_data(handle);
    if (NULL == data_ptr) return;

    callback = cb ? s_get_cv_croak(cb) : NULL;

    /* find out which callback to set */
    if (0 == strcmp(name, "alloc")) {
        /* clear the callback's current value first */
        if (NULL != data_ptr->alloc_cb) {
            SvREFCNT_dec(data_ptr->alloc_cb);
            data_ptr->alloc_cb = NULL;
        }
        /* set the CB */
        if (NULL != callback) {
            data_ptr->alloc_cb = SvREFCNT_inc(callback);
        }
    }
    else if (0 == strcmp(name, "close")) {
        /* clear the callback's current value first */
        if (NULL != data_ptr->close_cb) {
            SvREFCNT_dec(data_ptr->close_cb);
            data_ptr->close_cb = NULL;
        }
        /* set the CB */
        if (NULL != callback) {
            data_ptr->close_cb = SvREFCNT_inc(callback);
        }
    }
    else if (0 == strcmp(name, "timer")) {
        /* clear the callback's current value first */
        if (NULL != data_ptr->timer_cb) {
            SvREFCNT_dec(data_ptr->timer_cb);
            data_ptr->timer_cb = NULL;
        }
        /* set the CB */
        if (NULL != callback) {
            data_ptr->timer_cb = SvREFCNT_inc(callback);
        }
    }
    else {
        croak("Invalid event name (%s)", name);
    }
}

/* HANDLE callbacks */
static void handle_alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf)
{
    handle_data_t *data_ptr = uv_data(handle);
    buf->base = malloc(suggested_size);
    buf->len = suggested_size;

    /* nothing else to do if we don't have a callback to call */
    if (NULL == data_ptr || NULL == data_ptr->alloc_cb) return;

    /* provide info to the caller: invocant, suggested_size */
    dSP;
    ENTER;
    SAVETMPS;

    PUSHMARK (SP);
    EXTEND (SP, 2);
    PUSHs(handle_bless(handle)); /* invocant */
    PUSHs(newSViv(suggested_size));

    PUTBACK;
    call_sv (data_ptr->alloc_cb, G_VOID);
    SPAGAIN;

    FREETMPS;
    LEAVE;
}

static void handle_close_cb(uv_handle_t* handle)
{
    handle_data_t *data_ptr = uv_data(handle);

    /* call the close_cb if we have one */
    if (NULL != data_ptr && NULL != data_ptr->close_cb) {
        /* provide info to the caller: invocant */
        dSP;
        ENTER;
        SAVETMPS;

        PUSHMARK (SP);
        EXTEND (SP, 1);
        PUSHs(handle_bless(handle)); /* invocant */

        PUTBACK;
        call_sv (data_ptr->close_cb, G_VOID);
        SPAGAIN;

        FREETMPS;
        LEAVE;
    }
}

static void handle_timer_cb(uv_timer_t* handle)
{
    handle_data_t *data_ptr = uv_data(handle);
    /* nothing else to do if we don't have a callback to call */
    if (NULL == data_ptr || NULL == data_ptr->timer_cb) return;

    /* provide info to the caller: invocant */
    dSP;
    ENTER;
    SAVETMPS;

    PUSHMARK (SP);
    EXTEND (SP, 1);
    PUSHs(handle_bless((uv_handle_t *) handle)); /* invocant */

    PUTBACK;
    call_sv (data_ptr->timer_cb, G_VOID);
    SPAGAIN;

    FREETMPS;
    LEAVE;
}

static HV * uverror2const = NULL;

static SV* error_constant_dualvar(int uverror) {
	SV * ret = newSV();
	SvUPGRADE( ret, SVt_PVIV );
	sv_setpvs( ret, uv_strerror(uverror) );
	SvIVX( ret ) = uverror;
	SvIOK_on( ret );
	hv_store( uverror2const, &uverror, sizeof(uverror), ret, 0 );
	return ret;
}

MODULE = UV             PACKAGE = UV            PREFIX = uv_

PROTOTYPES: ENABLE

BOOT:
{
    PERL_MATH_INT64_LOAD_OR_CROAK;
	int i;
    static char *handle_stash_names[UV_HANDLE_TYPE_MAX] = {
		[UV_UNKNOWN_HANDLE] = NULL,
		[UV_ASYNC] = "UV::Async",
		[UV_CHECK] = "UV::Check",
		[UV_FS_EVENT] = "UV::FSEvent",
		[UV_FS_POLL] = "UV::FSPoll",
		[UV_ASYNC] = "UV::Async",
		[UV_CHECK] = "UV::Check",
		[UV_HANDLE] = "UV::Handle",
		[UV_IDLE] = "UV::Idle",
		[UV_NAMED_PIPE] = "UV::NamedPipe",
		[UV_POLL] = "UV::Poll",
		[UV_PREPARE] = "UV::Prepare",
		[UV_PROCESS] = "UV::Process",
		[UV_STREAM] = "UV::Stream",
		[UV_TCP] = "UV::TCP",
		[UV_TIMER] = "UV::Timer",
		[UV_TTY] = "UV::TTY",
		[UV_UDP] = "UV::UDP",
		[UV_SIGNAL] = "UV::Signal",
		[UV_FILE] = "UV::File"
	};
	static char *request_stash_names[UV_REQ_TYPE_MAX] = {
		[UV_UNKNOWN_REQ] = NULL,
		[UV_REQ] = "UV::Req",
		[UV_CONNECT] = "UV::Connect",
		[UV_WRITE] = "UV::Write",
		[UV_SHUTDOWN] = "UV::Shutdown",
		[UV_UDP_SEND] = "UV::UDP::Send",
		[UV_FS] = "UV::FS",
		[UV_WORK] = "UV::Work",
		[UV_GETADDRINFO] = "UV::GetAddrInfo",
		[UV_GETNAMEINFO] = "UV::GetNameInfo",
		[UV_REQ_TYPE_PRIVATE] = "UV::RquestTypePrivate"
	};
    HV *stash = gv_stashpvn("UV", 2, TRUE);
	
	uverror2const = newHV();

#define MYCONST(NAME) newCONSTSUB(stash, #NAME, newIV(NAME))
    /* expose the different request type constants */
    MYCONST(UV_REQ);
    MYCONST(UV_CONNECT);
    MYCONST(UV_WRITE);
    MYCONST(UV_SHUTDOWN);
    MYCONST(UV_UDP_SEND);
    MYCONST(UV_FS);
    MYCONST(UV_WORK);
    MYCONST(UV_GETADDRINFO);
    MYCONST(UV_GETNAMEINFO);

    /* expose the different handle type constants */
    MYCONST(UV_ASYNC);
    MYCONST(UV_CHECK);
    MYCONST(UV_FS_EVENT);
    MYCONST(UV_FS_POLL);
    MYCONST(UV_HANDLE);
    MYCONST(UV_IDLE);
    MYCONST(UV_NAMED_PIPE);
    MYCONST(UV_POLL);
    MYCONST(UV_PREPARE);
    MYCONST(UV_PROCESS);
    MYCONST(UV_STREAM);
    MYCONST(UV_TCP);
    MYCONST(UV_TIMER);
    MYCONST(UV_TTY);
    MYCONST(UV_UDP);
    MYCONST(UV_SIGNAL);
    MYCONST(UV_FILE);

    /* expose the different error constants */
#define MYERRCONST(NAME) newCONSTSUB(stash, #NAME, error_constant_dualvar(NAME))
    MYERRCONST(UV_E2BIG);
    MYERRCONST(UV_EACCES);
    MYERRCONST(UV_EADDRINUSE);
    MYERRCONST(UV_EADDRNOTAVAIL);
    MYERRCONST(UV_EAFNOSUPPORT);
    MYERRCONST(UV_EAGAIN);
    MYERRCONST(UV_EAI_ADDRFAMILY);
    MYERRCONST(UV_EAI_AGAIN);
    MYERRCONST(UV_EAI_BADFLAGS);
    MYERRCONST(UV_EAI_BADHINTS);
    MYERRCONST(UV_EAI_CANCELED);
    MYERRCONST(UV_EAI_FAIL);
    MYERRCONST(UV_EAI_FAMILY);
    MYERRCONST(UV_EAI_MEMORY);
    MYERRCONST(UV_EAI_NODATA);
    MYERRCONST(UV_EAI_NONAME);
    MYERRCONST(UV_EAI_OVERFLOW);
    MYERRCONST(UV_EAI_PROTOCOL);
    MYERRCONST(UV_EAI_SERVICE);
    MYERRCONST(UV_EAI_SOCKTYPE);
    MYERRCONST(UV_EALREADY);
    MYERRCONST(UV_EBADF);
    MYERRCONST(UV_EBUSY);
    MYERRCONST(UV_ECANCELED);
    MYERRCONST(UV_ECHARSET);
    MYERRCONST(UV_ECONNABORTED);
    MYERRCONST(UV_ECONNREFUSED);
    MYERRCONST(UV_ECONNRESET);
    MYERRCONST(UV_EDESTADDRREQ);
    MYERRCONST(UV_EEXIST);
    MYERRCONST(UV_EFAULT);
    MYERRCONST(UV_EFBIG);
    MYERRCONST(UV_EHOSTUNREACH);
    MYERRCONST(UV_EINTR);
    MYERRCONST(UV_EINVAL);
    MYERRCONST(UV_EIO);
    MYERRCONST(UV_EISCONN);
    MYERRCONST(UV_EISDIR);
    MYERRCONST(UV_ELOOP);
    MYERRCONST(UV_EMFILE);
    MYERRCONST(UV_EMSGSIZE);
    MYERRCONST(UV_ENAMETOOLONG);
    MYERRCONST(UV_ENETDOWN);
    MYERRCONST(UV_ENETUNREACH);
    MYERRCONST(UV_ENFILE);
    MYERRCONST(UV_ENOBUFS);
    MYERRCONST(UV_ENODEV);
    MYERRCONST(UV_ENOENT);
    MYERRCONST(UV_ENOMEM);
    MYERRCONST(UV_ENONET);
    MYERRCONST(UV_ENOPROTOOPT);
    MYERRCONST(UV_ENOSPC);
    MYERRCONST(UV_ENOSYS);
    MYERRCONST(UV_ENOTCONN);
    MYERRCONST(UV_ENOTDIR);
    MYERRCONST(UV_ENOTEMPTY);
    MYERRCONST(UV_ENOTSOCK);
    MYERRCONST(UV_ENOTSUP);
    MYERRCONST(UV_EPERM);
    MYERRCONST(UV_EPIPE);
    MYERRCONST(UV_EPROTO);
    MYERRCONST(UV_EPROTONOSUPPORT);
    MYERRCONST(UV_EPROTOTYPE);
    MYERRCONST(UV_ERANGE);
    MYERRCONST(UV_EROFS);
    MYERRCONST(UV_ESHUTDOWN);
    MYERRCONST(UV_ESPIPE);
    MYERRCONST(UV_ESRCH);
    MYERRCONST(UV_ETIMEDOUT);
    MYERRCONST(UV_ETXTBSY);
    MYERRCONST(UV_EXDEV);
    MYERRCONST(UV_UNKNOWN);
    MYERRCONST(UV_EOF);
    MYERRCONST(UV_ENXIO);
    MYERRCONST(UV_EMLINK);


    /* build out our stashes */
    stash_loop          = gv_stashpv("UV::Loop",        TRUE);
	for( i = 0; i < UV_HANDLE_TYPE_MAX; ++i ) {
		if( handle_stash_names[i] == NULL ) continue;
		handle_type2stash[i] = gv_stashpv(handle_stash_names[i], TRUE);
	}
	for( i = 0; i < ; ++i ) {
		if( request_stash_names[i] == NULL ) continue;
		request_type2stash[i] = gv_stashpv(request_stash_names[i], TRUE);
	}

    {
        SV *sv = perl_get_sv("EV::API", TRUE);
        uvapi.default_loop = NULL;
        sv_setiv (sv, (IV)&uvapi);
        SvREADONLY_on (sv);
    }
}


SV *uv_default_loop()
    CODE:
{
    loop_default_init();
    RETVAL = newSVsv(default_loop_sv);
}
    OUTPUT:
    RETVAL

uint64_t uv_hrtime()

MODULE = UV             PACKAGE = UV::Handle      PREFIX = uv_handle_

PROTOTYPES: ENABLE

BOOT:
{
    HV *stash = gv_stashpvn("UV::Handle", 10, TRUE);
}

void DESTROY(uv_handle_t *handle)
    CODE:
    handle_destroy(handle);

SV *uv_handle_loop(uv_handle_t *handle)
    CODE:
    RETVAL = newSVsv(uv_data(handle)->loop_sv);
    OUTPUT:
    RETVAL

int uv_handle_active (uv_handle_t *handle)
    CODE:
        RETVAL = uv_is_active(handle);
    OUTPUT:
    RETVAL

void uv_handle_close(uv_handle_t *handle, SV *cb=NULL)
    CODE:
    if (NULL != cb) {
        handle_on(handle, "close", cb);
    }
    uv_close(handle, handle_close_cb);

void uv_handle_on(uv_handle_t *handle, const char *name, SV *cb=NULL)
    CODE:
    handle_on(handle, name, cb);

int uv_handle_type(uv_handle_t *handle)
    CODE:
    RETVAL = handle->type;
    OUTPUT:
    RETVAL

MODULE = UV             PACKAGE = UV::Timer      PREFIX = uv_timer_

PROTOTYPES: ENABLE

BOOT:
{
    HV *stash = gv_stashpvn("UV::Timer", 9, TRUE);
}

SV * uv_timer_new(SV *klass, uv_loop_t *loop = uvapi.default_loop)
    CODE:
{
    int res;
    uv_timer_t *timer = (uv_timer_t *)handle_new(UV_TIMER);
    res = uv_timer_init(loop, timer);
    if (0 != res) {
        Safefree(timer);
        croak("Couldn't initialize timer (%i): %s", res, uv_strerror(res));
    }

    if (loop == uvapi.default_loop) {
        uv_data(timer)->loop_sv = default_loop_sv;
    }
    else {
        uv_data(timer)->loop_sv = sv_bless( newRV_noinc( newSViv( PTR2IV(loop))), stash_loop);
    }
    RETVAL = handle_bless((uv_handle_t *)timer);
}
    OUTPUT:
    RETVAL

void DESTROY(uv_timer_t *handle)
    CODE:
    if (NULL != handle && 0 == uv_is_closing((uv_handle_t *)handle) && 0 == uv_is_active((uv_handle_t *)handle)) {
        uv_timer_stop(handle);
        uv_close((uv_handle_t *)handle, handle_close_cb);
        handle_data_destroy(uv_data(handle));
    }

int uv_timer_start(uv_timer_t *handle, uint64_t start=0, uint64_t repeat=0, SV *cb=NULL)
    CODE:
        if (NULL != cb) {
            handle_on((uv_handle_t *)handle, "timer", cb);
        }
        RETVAL = uv_timer_start(handle, handle_timer_cb, start, repeat);
    OUTPUT:
    RETVAL

int uv_timer_stop(uv_timer_t *handle)
    CODE:
        RETVAL = uv_timer_stop(handle);
    OUTPUT:
    RETVAL

uint64_t uv_timer_get_repeat(uv_timer_t* handle)
    CODE:
        RETVAL = uv_timer_get_repeat(handle);
    OUTPUT:
    RETVAL

MODULE = UV             PACKAGE = UV::Loop      PREFIX = uv_

PROTOTYPES: ENABLE

BOOT:
{
    HV *stash = gv_stashpvn("UV::Loop", 8, TRUE);
    MYCONST(UV_RUN_DEFAULT);
    MYCONST(UV_RUN_ONCE);
    MYCONST(UV_RUN_NOWAIT);
}

SV *new (SV *klass, int want_default = 0)
    ALIAS:
        UV::Loop::default_loop = 1
        UV::Loop::default = 2
    CODE:
{
    uv_loop_t *loop;
    if (ix == 1 || ix == 2) want_default = 1;
    if (0 == want_default) {
        loop = loop_new();
        RETVAL = sv_bless(
            newRV_noinc(
                newSViv(
                    PTR2IV(loop)
                )
            ), stash_loop
        );
    }
    else {
        RETVAL = newSVsv(default_loop_sv);
    }
}
    OUTPUT:
    RETVAL

void DESTROY (uv_loop_t *loop)
    CODE:
    /* 1. the default loop shouldn't be freed by destroying it's perl loop object */
    /* 2. not doing so helps avoid many global destruction bugs in perl, too */
    if (loop == uvapi.default_loop) {
        SvREFCNT_dec (default_loop_sv);
        if (PL_dirty) {
            uv_loop_close((uv_loop_t *) default_loop_sv);
            default_loop_sv = NULL;
        }
    }
    else {
        if (0 == uv_loop_close(loop)) {
            Safefree(loop);
        }
    }

int uv_backend_fd(const uv_loop_t* loop)

int uv_backend_timeout(const uv_loop_t* loop)

int uv_close(uv_loop_t *loop)
    CODE:
        RETVAL = uv_loop_close(loop);
    OUTPUT:
    RETVAL

int uv_loop_alive(const uv_loop_t* loop)
ALIAS:
    UV::Loop::alive = 1

uint64_t uv_now(const uv_loop_t* loop)

int uv_run(uv_loop_t* loop, uv_run_mode mode=UV_RUN_DEFAULT)

void uv_stop(uv_loop_t* loop)

void uv_update_time(uv_loop_t* loop)
