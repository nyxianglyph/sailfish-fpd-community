/*
 * Fingerprint HAL access over libgbinder for AIDL-only devices
 * (android.hardware.biometrics.fingerprint.IFingerprint, V3 and later).
 *
 * Implements the u_hardware_biometry_* API the daemon was written against,
 * without an Android-side shim library. The parcel layouts follow the AIDL
 * definitions; UBports' biometryd (aidl_fingerprint_hal.cpp) was used as a
 * reference.
 *
 * Besides the fingerprint HAL this needs:
 *  - IGatekeeper (AIDL): enrolling requires a HardwareAuthToken, obtained by
 *    enrolling and verifying a fixed password for the challenge.
 *  - ISharedSecret: on Android keystore2 negotiates the HMAC key for auth
 *    tokens at boot. Nothing does that here, and without it Gatekeeper's
 *    verify fails, so it is done once at start.
 *  - Optionally Xiaomi's IXiaomiFingerprint: mfp-daemon only lights the
 *    under-display sensor when it has been told that an operation is running
 *    and that the UI is showing ("conditions").
 */
#include "../biometry.h"

#include <gbinder.h>
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define FP_IFACE   "android.hardware.biometrics.fingerprint.IFingerprint"
#define SES_IFACE  "android.hardware.biometrics.fingerprint.ISession"
#define CB_IFACE   "android.hardware.biometrics.fingerprint.ISessionCallback"
#define CAN_IFACE  "android.hardware.biometrics.common.ICancellationSignal"
#define GK_IFACE   "android.hardware.gatekeeper.IGatekeeper"
#define SS_IFACE   "android.hardware.security.sharedsecret.ISharedSecret"
#define XM_IFACE   "vendor.xiaomi.hardware.fingerprintextension.IXiaomiFingerprint"

#define LOG(fmt, ...) fprintf(stderr, "fp-gbinder: " fmt "\n", ##__VA_ARGS__)

/* IFingerprint */
enum { FP_GET_SENSOR_PROPS = 1, FP_CREATE_SESSION = 2 };
/* ISession */
enum {
    SES_GENERATE_CHALLENGE = 1, SES_REVOKE_CHALLENGE = 2, SES_ENROLL = 3,
    SES_AUTHENTICATE = 4, SES_ENUMERATE = 6, SES_REMOVE = 7, SES_CLOSE = 11
};
/* ISessionCallback */
enum {
    CB_CHALLENGE_GENERATED = 1, CB_CHALLENGE_REVOKED = 2, CB_ACQUIRED = 3,
    CB_ERROR = 4, CB_ENROLLMENT_PROGRESS = 5, CB_AUTH_SUCCEEDED = 6,
    CB_AUTH_FAILED = 7, CB_LOCKOUT_TIMED = 8, CB_LOCKOUT_PERMANENT = 9,
    CB_ENUMERATED = 12, CB_REMOVED = 13,
    CB_INTERFACE_VERSION = 16777215
};
/* IGatekeeper */
enum { GK_ENROLL = 3, GK_VERIFY = 4 };
/* Xiaomi condition indices and values */
enum { XM_COND_OVERLAY = 1, XM_COND_FADE = 2, XM_COND_POWER = 3, XM_COND_OP = 4,
       XM_COND_LOCKOUT = 5, XM_COND_KEYGUARD = 7 };
enum { XM_OP_ENROLL_START = 1, XM_OP_ENROLL_STOP = 2, XM_OP_AUTH_START = 3, XM_OP_AUTH_STOP = 4 };

typedef enum { OP_NONE, OP_ENROLL, OP_AUTH } Operation;

struct UHardwareBiometry_ {
    GBinderServiceManager *sm;
    GBinderClient *fp, *ses, *gk, *xm, *cancel;
    GBinderLocalObject *cb;
    gint32 sensor_id;
    UHardwareBiometryParams params;
    gboolean have_params;
    gint64 challenge;
    guint32 enroll_uid;
    gboolean enroll_pending;
    gboolean clear_pending;
    Operation op;
    gint32 *remove_ids;
    gint32 remove_count;
};

static const char gk_password[] = "default_password";

static GBinderClient *connect_to(GBinderServiceManager *sm, const char *name, const char *iface)
{
    int status = 0;
    GBinderRemoteObject *r = gbinder_servicemanager_get_service_sync(sm, name, &status);
    return r ? gbinder_client_new(r, iface) : NULL;
}

/* Sync call; on success the reader is positioned after the status word. */
static GBinderRemoteReply *call(GBinderClient *c, guint32 code, GBinderLocalRequest *req,
    GBinderReader *reader, const char *what)
{
    int status = 0;
    gint32 ex = -1;
    GBinderRemoteReply *reply;

    if (!c) {
        if (req)
            gbinder_local_request_unref(req);
        return NULL;
    }
    reply = gbinder_client_transact_sync_reply(c, code, req, &status);
    if (req)
        gbinder_local_request_unref(req);
    if (!reply || status != GBINDER_STATUS_OK) {
        LOG("%s: transaction failed, status %d", what, status);
        gbinder_remote_reply_unref(reply);
        return NULL;
    }
    gbinder_remote_reply_init_reader(reply, reader);
    if (!gbinder_reader_read_int32(reader, &ex) || ex != 0) {
        LOG("%s: exception %d", what, ex);
        gbinder_remote_reply_unref(reply);
        return NULL;
    }
    return reply;
}

static gboolean call_void(GBinderClient *c, guint32 code, GBinderLocalRequest *req, const char *what)
{
    GBinderReader reader;
    GBinderRemoteReply *reply = call(c, code, req, &reader, what);
    gbinder_remote_reply_unref(reply);
    return reply != NULL;
}

/* enroll() and authenticate() return an ICancellationSignal. */
static gboolean call_cancellable(UHardwareBiometry self, guint32 code, GBinderLocalRequest *req,
    const char *what)
{
    GBinderReader reader;
    GBinderRemoteObject *r;
    GBinderRemoteReply *reply = call(self->ses, code, req, &reader, what);

    if (!reply)
        return FALSE;
    r = gbinder_reader_read_object(&reader);
    gbinder_client_unref(self->cancel);
    self->cancel = r ? gbinder_client_new(r, CAN_IFACE) : NULL;
    gbinder_remote_reply_unref(reply);
    return TRUE;
}

static void append_bytes(GBinderWriter *w, const void *d, gsize n)
{
    /* An empty non-nullable byte[] is length 0, not the null marker -1. */
    if (n)
        gbinder_writer_append_byte_array(w, d, n);
    else
        gbinder_writer_append_int32(w, 0);
}

static gboolean read_parcelable_header(GBinderReader *r)
{
    gint32 nonnull = 0, size = 0;
    return gbinder_reader_read_int32(r, &nonnull) && nonnull &&
        gbinder_reader_read_int32(r, &size) && size >= 4;
}

/* ---- Xiaomi conditions ---- */

static void xm_condition(UHardwareBiometry self, int index, int value)
{
    GBinderLocalRequest *req;
    GBinderWriter w;

    if (!self->xm)
        return;
    req = gbinder_client_new_request(self->xm);
    gbinder_local_request_init_writer(req, &w);
    gbinder_writer_append_int32(&w, index);
    gbinder_writer_append_int32(&w, value);
    call_void(self->xm, 1, req, "IXiaomiFingerprint condition");
}

static void operation_started(UHardwareBiometry self, Operation op)
{
    self->op = op;
    xm_condition(self, XM_COND_OP, op == OP_ENROLL ? XM_OP_ENROLL_START : XM_OP_AUTH_START);
    xm_condition(self, XM_COND_OVERLAY, 1);
}

static void operation_stopped(UHardwareBiometry self)
{
    Operation op = self->op;

    if (op == OP_NONE)
        return;
    self->op = OP_NONE;
    xm_condition(self, XM_COND_OVERLAY, 0);
    xm_condition(self, XM_COND_OP, op == OP_ENROLL ? XM_OP_ENROLL_STOP : XM_OP_AUTH_STOP);
}

/*
 * Calls into the HAL must not be made from inside one of its callbacks: the
 * HAL waits for the callback to return while holding its own locks. Such
 * work is queued to the main loop instead.
 */
static gboolean idle_operation_stopped(gpointer data)
{
    operation_stopped(data);
    return G_SOURCE_REMOVE;
}

/* ---- shared secret ---- */

typedef struct {
    guint8 *raw; gsize rawlen;
    guint8 *seed; gsize seedlen;
    guint8 *nonce; gsize noncelen;
} SsParam;

static int bytes_cmp(const guint8 *a, gsize alen, const guint8 *b, gsize blen)
{
    gsize n = MIN(alen, blen);
    int c = n ? memcmp(a, b, n) : 0;
    if (!c && alen != blen)
        c = alen < blen ? -1 : 1;
    return c;
}

static int ss_cmp(const void *pa, const void *pb)
{
    const SsParam *a = pa, *b = pb;
    int c = bytes_cmp(a->seed, a->seedlen, b->seed, b->seedlen);
    return c ? c : bytes_cmp(a->nonce, a->noncelen, b->nonce, b->noncelen);
}

static void negotiate_shared_secret(GBinderServiceManager *sm)
{
    static const char *instances[] = { SS_IFACE "/default", SS_IFACE "/strongbox" };
    GBinderClient *clients[G_N_ELEMENTS(instances)];
    SsParam prm[G_N_ELEMENTS(instances)];
    guint n = 0, i, k;

    for (i = 0; i < G_N_ELEMENTS(instances); i++) {
        GBinderReader r, r2;
        GBinderRemoteReply *reply;
        gsize size = 0, l = 0;
        const guint8 *p, *b;
        GBinderClient *c = connect_to(sm, instances[i], SS_IFACE);

        if (!c)
            continue;
        reply = call(c, 1, NULL, &r, instances[i]);
        if (!reply) {
            gbinder_client_unref(c);
            continue;
        }
        r2 = r;
        p = gbinder_reader_read_parcelable(&r, &size);
        if (p && read_parcelable_header(&r2)) {
            prm[n].raw = g_memdup2(p, size);
            prm[n].rawlen = size;
            b = gbinder_reader_read_byte_array(&r2, &l);
            prm[n].seed = g_memdup2(b ? b : (const guint8 *)"", l);
            prm[n].seedlen = l;
            l = 0;
            b = gbinder_reader_read_byte_array(&r2, &l);
            prm[n].nonce = g_memdup2(b ? b : (const guint8 *)"", l);
            prm[n].noncelen = l;
            clients[n++] = c;
        } else {
            gbinder_client_unref(c);
        }
        gbinder_remote_reply_unref(reply);
    }
    if (!n) {
        LOG("no shared secret participant, auth tokens may not verify");
        return;
    }
    /* Every participant gets the same, sorted list. */
    qsort(prm, n, sizeof(prm[0]), ss_cmp);
    for (i = 0; i < n; i++) {
        GBinderWriter w;
        GBinderLocalRequest *req = gbinder_client_new_request(clients[i]);

        gbinder_local_request_init_writer(req, &w);
        gbinder_writer_append_int32(&w, n);
        for (k = 0; k < n; k++)
            gbinder_writer_append_parcelable(&w, prm[k].raw, prm[k].rawlen);
        if (call_void(clients[i], 2, req, "computeSharedSecret"))
            LOG("shared secret negotiated (%u participant%s)", n, n == 1 ? "" : "s");
        gbinder_client_unref(clients[i]);
    }
    for (i = 0; i < n; i++) {
        g_free(prm[i].raw);
        g_free(prm[i].seed);
        g_free(prm[i].nonce);
    }
}

/* ---- enroll ---- */

static void report_error(UHardwareBiometry self, UHardwareBiometryFingerprintError error, gint32 vendor)
{
    if (self->have_params && self->params.error_cb)
        self->params.error_cb(0, error, vendor, self->params.context);
}

/* Gatekeeper enroll + verify for the challenge, then ISession.enroll(). */
static gboolean idle_enroll_continue(gpointer data)
{
    UHardwareBiometry self = data;
    GBinderLocalRequest *req;
    GBinderRemoteReply *reply;
    GBinderReader r;
    GBinderWriter w;
    gint32 st = -1, timeout = 0, type = 0;
    gint64 sid = 0, ch = 0, user = 0, aid = 0, ts = 0;
    gsize hlen = 0, maclen = 0;
    const void *h, *mac;
    guint8 *handle;
    /* HardwareAuthToken: challenge, userId, authenticatorId, authenticatorType,
     * Timestamp parcelable {nonnull, size, ms}, mac byte[32]. */
    guint8 hat[8 + 8 + 8 + 4 + (4 + 4 + 8) + (4 + 32)];
    guint32 u32;

    if (!self->enroll_pending)
        return G_SOURCE_REMOVE;
    self->enroll_pending = FALSE;

    req = gbinder_client_new_request(self->gk);
    gbinder_local_request_init_writer(req, &w);
    gbinder_writer_append_int32(&w, self->enroll_uid);
    append_bytes(&w, NULL, 0);                              /* currentPasswordHandle */
    append_bytes(&w, NULL, 0);                              /* currentPassword */
    append_bytes(&w, gk_password, strlen(gk_password));     /* desiredPassword */
    reply = call(self->gk, GK_ENROLL, req, &r, "gatekeeper enroll");
    if (!reply)
        goto fail;
    if (!(read_parcelable_header(&r) && gbinder_reader_read_int32(&r, &st) &&
        gbinder_reader_read_int32(&r, &timeout) && gbinder_reader_read_int64(&r, &sid) &&
        (h = gbinder_reader_read_byte_array(&r, &hlen)) && st >= 0 && hlen)) {
        LOG("gatekeeper enroll failed: status %d, timeout %d", st, timeout);
        gbinder_remote_reply_unref(reply);
        goto fail;
    }
    handle = g_memdup2(h, hlen);
    gbinder_remote_reply_unref(reply);

    req = gbinder_client_new_request(self->gk);
    gbinder_local_request_init_writer(req, &w);
    gbinder_writer_append_int32(&w, self->enroll_uid);
    gbinder_writer_append_int64(&w, self->challenge);
    append_bytes(&w, handle, hlen);
    append_bytes(&w, gk_password, strlen(gk_password));
    reply = call(self->gk, GK_VERIFY, req, &r, "gatekeeper verify");
    g_free(handle);
    if (!reply)
        goto fail;
    st = -1;
    if (!(read_parcelable_header(&r) && gbinder_reader_read_int32(&r, &st) &&
        gbinder_reader_read_int32(&r, &timeout) && read_parcelable_header(&r) &&
        gbinder_reader_read_int64(&r, &ch) && gbinder_reader_read_int64(&r, &user) &&
        gbinder_reader_read_int64(&r, &aid) && gbinder_reader_read_int32(&r, &type) &&
        read_parcelable_header(&r) && gbinder_reader_read_int64(&r, &ts) &&
        (mac = gbinder_reader_read_byte_array(&r, &maclen)) && maclen == 32)) {
        LOG("gatekeeper verify failed: status %d, timeout %d", st, timeout);
        gbinder_remote_reply_unref(reply);
        goto fail;
    }
    memcpy(hat, &ch, 8);
    memcpy(hat + 8, &user, 8);
    memcpy(hat + 16, &aid, 8);
    memcpy(hat + 24, &type, 4);
    u32 = 1;  memcpy(hat + 28, &u32, 4);
    u32 = 12; memcpy(hat + 32, &u32, 4);
    memcpy(hat + 36, &ts, 8);
    u32 = 32; memcpy(hat + 44, &u32, 4);
    memcpy(hat + 48, mac, 32);
    gbinder_remote_reply_unref(reply);

    req = gbinder_client_new_request(self->ses);
    gbinder_local_request_init_writer(req, &w);
    gbinder_writer_append_parcelable(&w, hat, sizeof(hat));
    if (!call_cancellable(self, SES_ENROLL, req, "enroll"))
        goto fail;
    operation_started(self, OP_ENROLL);
    return G_SOURCE_REMOVE;

fail:
    report_error(self, ERROR_UNABLE_TO_PROCESS, 0);
    return G_SOURCE_REMOVE;
}

static gboolean idle_revoke_challenge(gpointer data)
{
    UHardwareBiometry self = data;
    GBinderLocalRequest *req = gbinder_client_new_request(self->ses);
    GBinderWriter w;

    gbinder_local_request_init_writer(req, &w);
    gbinder_writer_append_int64(&w, self->challenge);
    call_void(self->ses, SES_REVOKE_CHALLENGE, req, "revokeChallenge");
    return G_SOURCE_REMOVE;
}

static gboolean idle_remove_all(gpointer data)
{
    UHardwareBiometry self = data;
    GBinderLocalRequest *req = gbinder_client_new_request(self->ses);
    GBinderWriter w;
    gint32 i;

    gbinder_local_request_init_writer(req, &w);
    gbinder_writer_append_int32(&w, self->remove_count);
    for (i = 0; i < self->remove_count; i++)
        gbinder_writer_append_int32(&w, self->remove_ids[i]);
    g_free(self->remove_ids);
    self->remove_ids = NULL;
    self->remove_count = 0;
    if (!call_void(self->ses, SES_REMOVE, req, "removeEnrollments"))
        report_error(self, ERROR_UNABLE_TO_REMOVE, 0);
    return G_SOURCE_REMOVE;
}

/* ---- callbacks from the HAL ---- */

static UHardwareBiometryFingerprintError map_error(gint32 e)
{
    switch (e) {
    case 1: return ERROR_HW_UNAVAILABLE;
    case 2: return ERROR_UNABLE_TO_PROCESS;
    case 3: return ERROR_TIMEOUT;
    case 4: return ERROR_NO_SPACE;
    case 5: return ERROR_CANCELED;
    case 6: return ERROR_UNABLE_TO_REMOVE;
    case 7: return ERROR_VENDOR;
    case 8: return ERROR_HW_UNAVAILABLE;   /* BAD_CALIBRATION */
    default: return ERROR_UNABLE_TO_PROCESS;
    }
}

static UHardwareBiometryFingerprintAcquiredInfo map_acquired(gint32 info)
{
    /* AIDL: UNKNOWN 0, GOOD 1 ... TOO_FAST 6, VENDOR 7, then newer codes. */
    return (info >= 1 && info <= 7) ? info - 1 : ACQUIRED_VENDOR;
}

static gint32 *read_int_array(GBinderReader *r, gint32 *count)
{
    gint32 n = 0, i, *ids;

    *count = 0;
    if (!gbinder_reader_read_int32(r, &n) || n <= 0 || n > 1024)
        return NULL;
    ids = g_new0(gint32, n);
    for (i = 0; i < n; i++)
        gbinder_reader_read_int32(r, &ids[i]);
    *count = n;
    return ids;
}

static GBinderLocalReply *on_callback(GBinderLocalObject *obj, GBinderRemoteRequest *req,
    guint code, guint flags, int *status, void *user_data)
{
    UHardwareBiometry self = user_data;
    UHardwareBiometryParams *p = self->have_params ? &self->params : NULL;
    GBinderLocalReply *reply;
    GBinderReader r;
    gint32 a = 0, b = 0, n = 0, i, *ids;
    gint64 l = 0;

    gbinder_remote_request_init_reader(req, &r);
    switch (code) {
    case CB_CHALLENGE_GENERATED:
        gbinder_reader_read_int64(&r, &l);
        self->challenge = l;
        if (self->enroll_pending)
            g_idle_add(idle_enroll_continue, self);
        break;
    case CB_ACQUIRED:
        gbinder_reader_read_int32(&r, &a);
        gbinder_reader_read_int32(&r, &b);
        if (p && p->acquired_cb)
            p->acquired_cb(0, map_acquired(a), b, p->context);
        break;
    case CB_ERROR:
        gbinder_reader_read_int32(&r, &a);
        gbinder_reader_read_int32(&r, &b);
        LOG("HAL error %d (vendor %d)", a, b);
        g_idle_add(idle_operation_stopped, self);
        report_error(self, map_error(a), b);
        break;
    case CB_ENROLLMENT_PROGRESS:
        gbinder_reader_read_int32(&r, &a);
        gbinder_reader_read_int32(&r, &b);
        if (b == 0)
            g_idle_add(idle_operation_stopped, self);
        if (p && p->enrollresult_cb)
            p->enrollresult_cb(0, (guint32)a, 0, (guint32)b, p->context);
        break;
    case CB_AUTH_SUCCEEDED:
        gbinder_reader_read_int32(&r, &a);
        g_idle_add(idle_operation_stopped, self);
        if (p && p->authenticated_cb)
            p->authenticated_cb(0, (guint32)a, 0, p->context);
        break;
    case CB_AUTH_FAILED:
        /* Not matched; the operation keeps running. */
        if (p && p->authenticated_cb)
            p->authenticated_cb(0, 0, 0, p->context);
        break;
    case CB_LOCKOUT_TIMED:
    case CB_LOCKOUT_PERMANENT:
        g_idle_add(idle_operation_stopped, self);
        report_error(self, ERROR_LOCKOUT, 0);
        break;
    case CB_ENUMERATED:
        ids = read_int_array(&r, &n);
        if (self->clear_pending) {
            self->clear_pending = FALSE;
            if (n) {
                g_free(self->remove_ids);
                self->remove_ids = ids;
                self->remove_count = n;
                ids = NULL;
                g_idle_add(idle_remove_all, self);
            } else if (p && p->removed_cb) {
                p->removed_cb(0, 0, 0, 0, p->context);
            }
        } else if (p && p->enumerate_cb) {
            if (!n)
                p->enumerate_cb(0, 0, 0, 0, p->context);
            for (i = 0; i < n; i++)
                p->enumerate_cb(0, (guint32)ids[i], 0, n - 1 - i, p->context);
        }
        g_free(ids);
        break;
    case CB_REMOVED:
        ids = read_int_array(&r, &n);
        if (p && p->removed_cb) {
            if (!n)
                p->removed_cb(0, 0, 0, 0, p->context);
            for (i = 0; i < n; i++)
                p->removed_cb(0, (guint32)ids[i], 0, n - 1 - i, p->context);
        }
        g_free(ids);
        break;
    case CB_INTERFACE_VERSION:
        *status = GBINDER_STATUS_OK;
        reply = gbinder_local_object_new_reply(obj);
        gbinder_local_reply_append_int32(reply, 0);
        gbinder_local_reply_append_int32(reply, 3);
        return reply;
    default:
        break;
    }
    *status = GBINDER_STATUS_OK;
    if (flags & GBINDER_TX_FLAG_ONEWAY)
        return NULL;
    reply = gbinder_local_object_new_reply(obj);
    gbinder_local_reply_append_int32(reply, 0);
    return reply;
}

static void hal_died(GBinderRemoteObject *obj, void *user_data)
{
    /* The session is gone with the HAL; let the service manager restart us. */
    LOG("fingerprint HAL died, exiting");
    _exit(1);
}

/* ---- API ---- */

static gboolean read_sensor_props(UHardwareBiometry self)
{
    GBinderReader r;
    GBinderRemoteReply *reply = call(self->fp, FP_GET_SENSOR_PROPS, NULL, &r, "getSensorProps");
    gint32 count = 0, type = -1;
    gsize size = 0;
    gboolean ok = FALSE;

    if (!reply)
        return FALSE;
    if (gbinder_reader_read_int32(&r, &count) && count > 0) {
        /* SensorProps starts with the CommonProps parcelable, whose first
         * field is the sensor id; the sensor type follows CommonProps. */
        const guint8 *p = gbinder_reader_read_parcelable(&r, &size);
        if (p && size >= 12) {
            guint32 common_size;
            memcpy(&common_size, p + 4, 4);
            memcpy(&self->sensor_id, p + 8, 4);
            if (4 + (gsize)common_size + 4 <= size)
                memcpy(&type, p + 4 + common_size, 4);
            ok = TRUE;
        }
    }
    gbinder_remote_reply_unref(reply);
    if (ok)
        LOG("sensor id %d, type %d", self->sensor_id, type);
    return ok;
}

static gboolean create_session(UHardwareBiometry self)
{
    GBinderReader r;
    GBinderWriter w;
    GBinderRemoteObject *o;
    GBinderRemoteReply *reply;
    GBinderLocalRequest *req = gbinder_client_new_request(self->fp);

    gbinder_local_request_init_writer(req, &w);
    gbinder_writer_append_int32(&w, self->sensor_id);
    gbinder_writer_append_int32(&w, 0);     /* Android user id */
    gbinder_writer_append_local_object(&w, self->cb);
    reply = call(self->fp, FP_CREATE_SESSION, req, &r, "createSession");
    if (!reply)
        return FALSE;
    o = gbinder_reader_read_object(&r);
    gbinder_remote_reply_unref(reply);
    if (!o)
        return FALSE;
    self->ses = gbinder_client_new(o, SES_IFACE);
    return TRUE;
}

UHardwareBiometry u_hardware_biometry_new()
{
    UHardwareBiometry self = g_new0(struct UHardwareBiometry_, 1);
    const char *instance = getenv("FPD_HAL_INSTANCE");
    char name[160];
    int status = 0, i;
    GBinderRemoteObject *remote = NULL;

    snprintf(name, sizeof(name), FP_IFACE "/%s", instance ? instance : "default");
    self->sm = gbinder_servicemanager_new("/dev/binder");
    if (!self->sm || !gbinder_servicemanager_wait(self->sm, 30000)) {
        LOG("no binder service manager");
        return self;
    }
    /* The HAL is a late_start service; give it time at boot. */
    for (i = 0; i < 60 && !remote; i++) {
        remote = gbinder_servicemanager_get_service_sync(self->sm, name, &status);
        if (!remote)
            sleep(1);
    }
    if (!remote) {
        LOG("%s not found", name);
        return self;
    }
    self->fp = gbinder_client_new(remote, FP_IFACE);
    gbinder_remote_object_add_death_handler(remote, hal_died, self);
    self->gk = connect_to(self->sm, GK_IFACE "/default", GK_IFACE);
    self->xm = connect_to(self->sm, XM_IFACE "/default", XM_IFACE);
    if (!self->gk)
        LOG("no AIDL gatekeeper, enrolling will not work");

    negotiate_shared_secret(self->sm);

    self->cb = gbinder_servicemanager_new_local_object(self->sm, CB_IFACE, on_callback, self);
    gbinder_local_object_set_stability(self->cb, GBINDER_STABILITY_VINTF);
    if (!read_sensor_props(self) || !create_session(self)) {
        LOG("could not create a HAL session");
        return self;
    }
    if (self->xm) {
        /* Display on, no colour fade, no lockout, not in low-brightness keyguard. */
        xm_condition(self, XM_COND_POWER, 2);
        xm_condition(self, XM_COND_FADE, 0);
        xm_condition(self, XM_COND_LOCKOUT, 0);
        xm_condition(self, XM_COND_KEYGUARD, 0);
    }
    LOG("using %s%s", name, self->xm ? " with Xiaomi extension" : "");
    return self;
}

uint64_t u_hardware_biometry_setNotify(UHardwareBiometry self, UHardwareBiometryParams *params)
{
    if (!self || !params)
        return 0;
    self->params = *params;
    self->have_params = TRUE;
    return 0;
}

uint64_t u_hardware_biometry_preEnroll(UHardwareBiometry self)
{
    /* The challenge is generated as part of enroll(). */
    return 0;
}

UHardwareBiometryRequestStatus u_hardware_biometry_enroll(UHardwareBiometry self, uint32_t gid,
    uint32_t timeoutSec, uint32_t uid)
{
    if (!self || !self->ses || !self->gk)
        return SYS_UNKNOWN;
    self->enroll_uid = uid;
    self->enroll_pending = TRUE;
    /* Continues in idle_enroll_continue() once the challenge arrives. */
    if (!call_void(self->ses, SES_GENERATE_CHALLENGE, NULL, "generateChallenge")) {
        self->enroll_pending = FALSE;
        return SYS_UNKNOWN;
    }
    return SYS_OK;
}

UHardwareBiometryRequestStatus u_hardware_biometry_postEnroll(UHardwareBiometry self)
{
    if (!self || !self->ses)
        return SYS_UNKNOWN;
    /* Called from the enrollment callback, see idle_operation_stopped(). */
    g_idle_add(idle_revoke_challenge, self);
    return SYS_OK;
}

uint64_t u_hardware_biometry_getAuthenticatorId(UHardwareBiometry self)
{
    return 0;
}

UHardwareBiometryRequestStatus u_hardware_biometry_cancel(UHardwareBiometry self)
{
    if (!self || !self->ses)
        return SYS_UNKNOWN;
    self->enroll_pending = FALSE;
    if (self->cancel) {
        call_void(self->cancel, 1, NULL, "cancel");
        gbinder_client_unref(self->cancel);
        self->cancel = NULL;
    }
    operation_stopped(self);
    return SYS_OK;
}

UHardwareBiometryRequestStatus u_hardware_biometry_enumerate(UHardwareBiometry self)
{
    if (!self || !self->ses)
        return SYS_UNKNOWN;
    self->clear_pending = FALSE;
    return call_void(self->ses, SES_ENUMERATE, NULL, "enumerateEnrollments") ? SYS_OK : SYS_UNKNOWN;
}

UHardwareBiometryRequestStatus u_hardware_biometry_remove(UHardwareBiometry self, uint32_t gid,
    uint32_t fid)
{
    GBinderLocalRequest *req;
    GBinderWriter w;

    if (!self || !self->ses)
        return SYS_UNKNOWN;
    if (fid == 0) {
        /* Remove everything: AIDL wants the ids, so list them first. */
        self->clear_pending = TRUE;
        if (!call_void(self->ses, SES_ENUMERATE, NULL, "enumerateEnrollments")) {
            self->clear_pending = FALSE;
            return SYS_UNKNOWN;
        }
        return SYS_OK;
    }
    req = gbinder_client_new_request(self->ses);
    gbinder_local_request_init_writer(req, &w);
    gbinder_writer_append_int32(&w, 1);
    gbinder_writer_append_int32(&w, (gint32)fid);
    return call_void(self->ses, SES_REMOVE, req, "removeEnrollments") ? SYS_OK : SYS_UNKNOWN;
}

UHardwareBiometryRequestStatus u_hardware_biometry_setActiveGroup(UHardwareBiometry self,
    uint32_t gid, char *storePath)
{
    /* AIDL sessions are per Android user; the HAL picks its own store. */
    return (self && self->ses) ? SYS_OK : SYS_UNKNOWN;
}

UHardwareBiometryRequestStatus u_hardware_biometry_authenticate(UHardwareBiometry self,
    uint64_t operationId, uint32_t gid)
{
    GBinderLocalRequest *req;
    GBinderWriter w;

    if (!self || !self->ses)
        return SYS_UNKNOWN;
    req = gbinder_client_new_request(self->ses);
    gbinder_local_request_init_writer(req, &w);
    gbinder_writer_append_int64(&w, (gint64)operationId);
    if (!call_cancellable(self, SES_AUTHENTICATE, req, "authenticate"))
        return SYS_UNKNOWN;
    operation_started(self, OP_AUTH);
    return SYS_OK;
}
