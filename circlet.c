#include <janet.h>
#include "mongoose.h"
#include <stdio.h>

typedef struct {
    struct mg_connection *conn;
    JanetFiber *fiber;
} ConnectionWrapper;

static int connection_mark(void *p, size_t size) {
    (void) size;
    ConnectionWrapper *cw = (ConnectionWrapper *)p;
    struct mg_connection *conn = cw->conn;
    JanetFiber *fiber = cw->fiber;
    janet_mark(janet_wrap_fiber(fiber));
    janet_mark(janet_wrap_abstract(conn->mgr));
    return 0;
}

static struct JanetAbstractType Connection_jt = {
    "mongoose.connection",
    NULL,
    connection_mark,
#ifdef JANET_ATEND_GCMARK
    JANET_ATEND_GCMARK
#endif
};

static int manager_gc(void *p, size_t size) {
    (void) size;
    mg_mgr_free((struct mg_mgr *) p);
    return 0;
}

static int manager_mark(void *p, size_t size) {
    (void) size;
    struct mg_mgr *mgr = (struct mg_mgr *)p;
    /* Iterate all connections, and mark then */
    struct mg_connection *conn = mgr->conns;
    while (conn) {
        ConnectionWrapper *cw = conn->fn_data;
        if (cw) {
            janet_mark(janet_wrap_abstract(cw));
        }
        conn = conn->next;
    }
    return 0;
}

static struct JanetAbstractType Manager_jt = {
    "mongoose.manager",
    manager_gc,
    manager_mark,
#ifdef JANET_ATEND_GCMARK
    JANET_ATEND_GCMARK
#endif
};

static Janet cfun_poll(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    struct mg_mgr *mgr = janet_getabstract(argv, 0, &Manager_jt);
    int32_t wait = janet_getinteger(argv, 1);
    mg_mgr_poll(mgr, wait);
    return argv[0];
}

static Janet mg2janetstr(struct mg_str str) {
    return janet_stringv((const uint8_t *) str.ptr, str.len);
}

/* Turn a string value into c string */
static const char *getstring(Janet x, const char *dflt) {
    if (janet_checktype(x, JANET_STRING)) {
        const uint8_t *bytes = janet_unwrap_string(x);
        return (const char *)bytes;
    } else {
        return dflt;
    }
}

static Janet build_http_request(struct mg_connection *c, struct mg_http_message *hm) {
    JanetTable *payload = janet_table(10);
    janet_table_put(payload, janet_ckeywordv("body"), mg2janetstr(hm->body));
    janet_table_put(payload, janet_ckeywordv("uri"), mg2janetstr(hm->uri));
    janet_table_put(payload, janet_ckeywordv("query-string"), mg2janetstr(hm->query));
    janet_table_put(payload, janet_ckeywordv("method"), mg2janetstr(hm->method));
    janet_table_put(payload, janet_ckeywordv("protocol"), mg2janetstr(hm->proto));
    janet_table_put(payload, janet_ckeywordv("connection"), janet_wrap_abstract(c->fn_data));
    /* Add headers */
    JanetTable *headers = janet_table(5);
    for (int i = 0; i < MG_MAX_HTTP_HEADERS; i++) {
        if (sizeof(hm->headers) == 0)
            break;
        Janet key = mg2janetstr(hm->headers[i].name);
        Janet value = mg2janetstr(hm->headers[i].value);
        Janet header = janet_table_get(headers, key);
        switch (janet_type(header)) {
            case JANET_NIL:
                janet_table_put(headers, key, value);
                break;
            case JANET_ARRAY:
                janet_array_push(janet_unwrap_array(header), value);
                break;
            default:
                {
                    Janet newHeader[2] = { header, value };
                    janet_table_put(headers, key, janet_wrap_array(janet_array_n(newHeader, 2)));
                    break;
                }
        }
    }
    janet_table_put(payload, janet_ckeywordv("headers"), janet_wrap_table(headers));
    return janet_wrap_table(payload);
}

void mg_send_response_line(struct mg_connection *nc, int status_code,
                           const char *extra_headers) {
  const char *status_message = "OK";
  switch (status_code) {
    case 206:
      status_message = "Partial Content";
      break;
    case 301:
      status_message = "Moved";
      break;
    case 302:
      status_message = "Found";
      break;
    case 401:
      status_message = "Unauthorized";
      break;
    case 403:
      status_message = "Forbidden";
      break;
    case 404:
      status_message = "Not Found";
      break;
    case 416:
      status_message = "Requested range not satisfiable";
      break;
    case 418:
      status_message = "I'm a teapot";
      break;
    case 500:
      status_message = "Internal Server Error";
      break;
  }
  mg_printf(nc, "HTTP/1.1 %d %s\r\nServer: %s\r\n", status_code, status_message,
            "Mongoose/" MG_VERSION);
  if (extra_headers != NULL) {
    mg_printf(nc, "%s\r\n", extra_headers);
  }
}

void mg_send_head(struct mg_connection *c, int status_code,
                  int64_t content_length, const char *extra_headers) {
  mg_send_response_line(c, status_code, extra_headers);
  if (content_length < 0) {
    mg_printf(c, "%s", "Transfer-Encoding: chunked\r\n");
  } else {
    mg_printf(c, "Content-Length: %\r\n", content_length);
  }
  mg_send(c, "\r\n", 2);
}

/* Send an HTTP reply. This should try not to panic, as at this point we
 * are outside of the janet interpreter. Instead, send a 500 response with
 * some formatted error message. */
static void send_http(struct mg_connection *c, Janet res, void *ev_data) {
    switch (janet_type(res)) {
        default:
            mg_send_head(c, 500, 0, "");
            break;
        case JANET_TABLE:
        case JANET_STRUCT:
            {
                const JanetKV *kvs;
                int32_t kvlen, kvcap;
                janet_dictionary_view(res, &kvs, &kvlen, &kvcap);

                /* Get response kind and check for special handling methods. */
                Janet kind = janet_dictionary_get(kvs, kvcap, janet_ckeywordv("kind"));
                if (janet_checktype(kind, JANET_KEYWORD)) {
                    const uint8_t *kindstr = janet_unwrap_keyword(kind);

                    /* Check for serving static files */
                    if (!janet_cstrcmp(kindstr, "static")) {
                        /* Construct static serve options */
                        struct mg_http_serve_opts *opts;
                        memset(&opts, 0, sizeof(opts));
                        Janet root = janet_dictionary_get(kvs, kvcap, janet_ckeywordv("root"));
                        opts->root_dir = getstring(root, NULL);
                        mg_http_serve_dir(c, (struct mg_http_message *) ev_data, opts);
                        return;
                    }

                    /* Check for serving single file */
                    if (!janet_cstrcmp(kindstr, "file")) {
                        Janet filev = janet_dictionary_get(kvs, kvcap, janet_ckeywordv("file"));
                        Janet mimev = janet_dictionary_get(kvs, kvcap, janet_ckeywordv("mime"));
                        const char *mime = getstring(mimev, "text/plain");
                        const char *filepath;
                        if (!janet_checktype(filev, JANET_STRING)) {
                            mg_send_head(c, 500, 0, "expected string :file option to serve a file");
                            break;
                        }
                        filepath = getstring(filev, "");
                        struct mg_http_serve_opts *opts;
                        memset(&opts, 0, sizeof(opts));
                        opts->mime_types = mime;
                        opts->extra_headers = "";
                        mg_http_serve_file(c, (struct mg_http_message *)ev_data, filepath, opts);
                        return;
                    }
                }

                /* Serve a generic HTTP response */

                Janet status = janet_dictionary_get(kvs, kvcap, janet_ckeywordv("status"));
                Janet headers = janet_dictionary_get(kvs, kvcap, janet_ckeywordv("headers"));
                Janet body = janet_dictionary_get(kvs, kvcap, janet_ckeywordv("body"));

                int code;
                if (janet_checktype(status, JANET_NIL))
                    code = 200;
                else if (janet_checkint(status))
                    code = janet_unwrap_integer(status);
                else
                    break;

                const JanetKV *headerkvs;
                int32_t headerlen, headercap;
                if (janet_checktype(headers, JANET_NIL)) {
                    headerkvs = NULL;
                    headerlen = 0;
                    headercap = 0;
                } else if (!janet_dictionary_view(headers, &headerkvs, &headerlen, &headercap)) {
                    break;
                }

                const uint8_t *bodybytes;
                int32_t bodylen;
                if (janet_checktype(body, JANET_NIL)) {
                    bodybytes = NULL;
                    bodylen = 0;
                } else if (!janet_bytes_view(body, &bodybytes, &bodylen)) {
                    break;
                }

                mg_send_response_line(c, code, NULL);
                for (const JanetKV *kv = janet_dictionary_next(headerkvs, headercap, NULL);
                        kv;
                        kv = janet_dictionary_next(headerkvs, headercap, kv)) {
                    const uint8_t *name = janet_to_string(kv->key);
                    int32_t header_len;
                    const Janet *header_items;
                    if (janet_indexed_view(kv->value, &header_items, &header_len)) {
                        /* Array-like of headers */
                        for (int32_t i = 0; i < header_len; i++) {
                            const uint8_t *value = janet_to_string(header_items[i]);
                            mg_printf(c, "%s: %s\r\n", (const char *)name, (const char *)value);
                        }
                    } else {
                        /* Single header */
                        const uint8_t *value = janet_to_string(kv->value);
                        mg_printf(c, "%s: %s\r\n", (const char *)name, (const char *)value);
                    }
                }

                mg_printf(c, "Content-Length: %d\r\n", bodylen);
                mg_printf(c, "\r\n");
                if (bodylen) mg_send(c, bodybytes, bodylen);
            }
            break;
    }
    mg_printf(c, "\r\n");
    c->is_draining = 1;
}

/* The dispatching event handler. This handler is what
 * is presented to mongoose, but it dispatches to dynamically
 * defined handlers. */
static void http_handler(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
    Janet evdata;
    switch (ev) {
        default:
            return;
        case MG_EV_HTTP_MSG:
            evdata = build_http_request(c, (struct mg_http_message *)ev_data);
            break;
    }
    ConnectionWrapper *cw;
    JanetFiber *fiber;
    cw = (ConnectionWrapper *)(c->fn_data);
    fiber = cw->fiber;
    Janet out;
    JanetSignal status = janet_continue(fiber, evdata, &out);
    if (status != JANET_SIGNAL_OK && status != JANET_SIGNAL_YIELD) {
        janet_stacktrace(fiber, out);
        return;
    }
    send_http(c, out, ev_data);
}

static Janet cfun_manager(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 0);
    (void) argv;
    void *mgr = janet_abstract(&Manager_jt, sizeof(struct mg_mgr));
    mg_mgr_init(mgr);
    return janet_wrap_abstract(mgr);
}

/* Common functionality for binding */
static void do_bind(int32_t argc, Janet *argv, struct mg_connection **connout,
        void (*handler)(struct mg_connection *, int, void *, void *)) {
    janet_fixarity(argc, 3);

    struct mg_mgr *mgr = janet_getabstract(argv, 0, &Manager_jt);
    const uint8_t *port = janet_getstring(argv, 1);
    JanetFunction *onConnection = janet_getfunction(argv, 2);

    struct mg_connection *conn = mg_http_listen(mgr, (const char *)port, handler, mgr);
    if (NULL == conn) {
        janet_panicf("could not bind to %s, reason being: %s", port);
    }
    JanetFiber *fiber = janet_fiber(onConnection, 64, 0, NULL);
    ConnectionWrapper *cw = janet_abstract(&Connection_jt, sizeof(ConnectionWrapper));
    cw->conn = conn;
    cw->fiber = fiber;
    conn->fn_data = cw;
    Janet out;
    JanetSignal status = janet_continue(fiber, janet_wrap_abstract(cw), &out);
    if (status != JANET_SIGNAL_YIELD) {
        janet_stacktrace(fiber, out);
    }
    *connout = conn;
}

static Janet cfun_bind_http(int32_t argc, Janet *argv) {
    struct mg_connection *conn = NULL;
    do_bind(argc, argv, &conn, http_handler);
    /*mg_set_protocol_http_websocket(conn);*/
    return argv[0];
}



static int is_websocket(const struct mg_connection *nc) {
    return nc->is_websocket;
}

static Janet build_websocket_event(struct mg_connection *c, Janet event, struct mg_ws_message *wm) {
    JanetTable *payload;
    if (wm) {
       payload = janet_table(4);
       janet_table_put(payload, janet_ckeywordv("data"), janet_stringv((const uint8_t *) wm->data.ptr, (int)wm->data.len));
    } else {
       payload = janet_table(3);
    }

    janet_table_put(payload, janet_ckeywordv("event"), event);
    janet_table_put(payload, janet_ckeywordv("protocol"), janet_cstringv("websocket"));
    janet_table_put(payload, janet_ckeywordv("connection"), janet_wrap_abstract(c->fn_data));
    return janet_wrap_table(payload);
}

/* The dispatching event handler. This handler is what
 * is presented to mongoose, but it dispatches to dynamically
 * defined handlers. */
static void http_websocket_handler(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
    Janet evdata;

    switch (ev) {
        default:
            return;

        case MG_EV_HTTP_MSG: {
            http_handler(c, ev, ev_data, fn_data);
            return;
        }

        case MG_EV_WS_OPEN: {
            evdata = build_websocket_event(c, janet_ckeywordv("open"), NULL);
            break;
        }

        case MG_EV_WS_MSG: {
            struct mg_ws_message *wm = (struct mg_ws_message *) ev_data;
            evdata = build_websocket_event(c, janet_ckeywordv("message"), wm);
            break;
        }

        case MG_EV_CLOSE: {
            evdata = build_websocket_event(c, janet_ckeywordv("close"), NULL);
            break;
        }

    }

    ConnectionWrapper *cw;
    JanetFiber *fiber;
    cw = (ConnectionWrapper *)(c->fn_data);
    fiber = cw->fiber;
    Janet out;
    JanetSignal status = janet_continue(fiber, evdata, &out);
    if (status != JANET_SIGNAL_OK && status != JANET_SIGNAL_YIELD) {
        janet_stacktrace(fiber, out);
        return;
    }
}

static Janet cfun_bind_http_websocket(int32_t argc, Janet *argv) {
    struct mg_connection *conn = NULL;
    do_bind(argc, argv, &conn, http_websocket_handler);
    /*mg_set_protocol_http_websocket(conn);*/
    return argv[0];
}

static Janet cfun_broadcast(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 2);
    struct mg_mgr *mgr = janet_getabstract(argv, 0, &Manager_jt);
    const char *buf = janet_getcstring(argv, 1);
    struct mg_connection *c;
    for (c = mgr->conns; c != NULL; c = c->next) {
      mg_ws_send(c, buf, strlen(buf), WEBSOCKET_OP_TEXT);
    }
    return argv[0];
}

static const JanetReg cfuns[] = {
    {"manager", cfun_manager, NULL},
    {"poll", cfun_poll, NULL},
    {"bind-http", cfun_bind_http, NULL},
    {"broadcast", cfun_broadcast, NULL},
    {"bind-http-websocket", cfun_bind_http_websocket, NULL},
    {NULL, NULL, NULL}
};

extern const unsigned char *circlet_lib_embed;
extern size_t circlet_lib_embed_size;

JANET_MODULE_ENTRY(JanetTable *env) {
    janet_cfuns(env, "circlet", cfuns);
    janet_dobytes(env,
            circlet_lib_embed,
            circlet_lib_embed_size,
            "circlet_lib.janet",
            NULL);
}
