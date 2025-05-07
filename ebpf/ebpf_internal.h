#define SEC_TO_NSEC(v) ((v)*1000000000ULL)
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define MAX_REUSEPORT_GROUPS 512
#define MAX_TOTAL_FLOWS 8192

#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
/* This is so hard. So. We want to avoid putting mess on stack, since
 * struct msg_value is large, reserve mem for it - on ringbuf. Only
 * then do snprintf, but we don't want to submit too large block to
 * ringbuf to avoid wasting space _there_. Threfore do
 * bpf_ringbuf_output, to copy the msg there and discard the original
 * allocation. Basically, we're using ringbuf as a malloc. Hurray. */
#define log_printf(fmt, args...)                                                         \
	({                                                                               \
		static const char *___fmt = fmt;                                         \
		unsigned long long ___param[___bpf_narg(args)];                          \
                                                                                         \
		_Pragma("GCC diagnostic push")                                           \
			_Pragma("GCC diagnostic ignored \"-Wint-conversion\"")           \
				___bpf_fill(___param, args);                             \
		_Pragma("GCC diagnostic pop")                                            \
                                                                                         \
			struct msg_value *e = bpf_ringbuf_reserve(                       \
				&msg_rb, sizeof(struct msg_value), 0);                   \
		if (e != NULL) {                                                         \
			long l = bpf_snprintf(&e->log[0], sizeof(e->log), ___fmt,        \
					      ___param, sizeof(___param));               \
			unsigned ll = offsetof(struct msg_value, log) + l;               \
			if (ll > sizeof(struct msg_value))                               \
				ll = sizeof(struct msg_value);                           \
			bpf_ringbuf_output(&msg_rb, e, ll, 0);                           \
			bpf_ringbuf_discard(e, 0);                                       \
		}                                                                        \
	})

#define log_printfs(_skey, fmt, args...)				\
	({                                                                               \
		static const char *___fmt = fmt;                                         \
		unsigned long long ___param[___bpf_narg(args)];                          \
                                                                                         \
		_Pragma("GCC diagnostic push")                                           \
			_Pragma("GCC diagnostic ignored \"-Wint-conversion\"")           \
				___bpf_fill(___param, args);                             \
		_Pragma("GCC diagnostic pop")                                            \
                                                                                         \
			struct msg_value *_e = bpf_ringbuf_reserve(                       \
				&msg_rb, sizeof(struct msg_value), 0);                   \
		if (_e != NULL) {					\
			_e->skey = *(_skey);				\
			long l = bpf_snprintf(&_e->log[0], sizeof(_e->log), ___fmt,        \
					      ___param, sizeof(___param));               \
			unsigned ll = offsetof(struct msg_value, log) + l;               \
			if (ll > sizeof(struct msg_value))                               \
				ll = sizeof(struct msg_value);                           \
			bpf_ringbuf_output(&msg_rb, _e, ll, 0);                           \
			bpf_ringbuf_discard(_e, 0);                                       \
		}                                                                        \
	})

/* Global metrics
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, unsigned int);
	__type(value, metrics_t);
} metrics_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 512 * 1024);
} msg_rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct socket_storage);
} sk_storage_map SEC(".maps");

#define PERCPU_ARRAY_SIZE 0x400
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__uint(value_size, PERCPU_ARRAY_SIZE);
	__uint(max_entries, 1);
} percpu_array_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_REUSEPORT_GROUPS);
	__type(key, struct reuseport_storage_key);
	__type(value, struct reuseport_storage);
} reuseport_storage_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__uint(max_entries, MAX_SOCKETS_IN_GEN *MAX_GENS);
	__uint(key_size, sizeof(uint64_t));
	__uint(value_size, sizeof(uint64_t));
} sockhash SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(map_flags, BPF_F_NO_COMMON_LRU); // LRU should be per-CPU, for undetermined
						// speed gains on flow table contention.
	__uint(max_entries, MAX_TOTAL_FLOWS);
	__uint(key_size, sizeof(struct lru_key));
	__uint(value_size, sizeof(struct lru_value));
} lru_map SEC(".maps");

#define METRIC_INC(token) __sync_fetch_and_add(&state->token, 1ULL)

struct ip_flow_hash {
	uint32_t remote_ip[4];
	uint32_t reuseport_group_id;
	uint16_t remote_port;
} __attribute__((packed));
