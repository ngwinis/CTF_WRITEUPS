typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;
typedef int s32;
typedef long usize;

#define DEV_PATH "/dev/challenge"

#define SYS_write  1
#define SYS_open   2
#define SYS_close  3
#define SYS_ioctl 16
#define SYS_mmap   9
#define SYS_exit  60

#define O_RDWR 2
#define PROT_READ  1
#define PROT_WRITE 2
#define MAP_PRIVATE   2
#define MAP_ANONYMOUS 32

#define IOCTL_GET_X      0x80046481u
#define IOCTL_GET_Y      0x80046482u
#define IOCTL_GET_Z      0x80046483u
#define IOCTL_GET_STATUS 0x80046485u
#define IOCTL_GET_EXITS  0x80046486u
#define IOCTL_GET_FLAG   0x80406487u
#define IOCTL_MOVE       0x40046488u
#define IOCTL_RESET      0x00006489u

enum { ROOM_NORMAL=0, ROOM_GOAL=1, ROOM_TRAP=2 };

struct Slot {
    s32 x, y, z;
    u8 used;
    u8 pad[3];
};

struct Frame {
    s32 x, y, z;
    u32 exits;
    u8 next_dir;
    signed char incoming;
    u16 pad;
};

static const s32 DX[6] = { 0,  1, 0, -1, 0,  0 };
static const s32 DY[6] = { -1, 0, 1,  0, 0,  0 };
static const s32 DZ[6] = { 0,  0, 0,  0, 1, -1 };
static const u8  OPP[6]= { 2,  3, 0,  1, 5,  4 };

static inline long sc1(long n, long a1) {
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a1) : "rcx","r11","memory");
    return r;
}
static inline long sc3(long n, long a1, long a2, long a3) {
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a1), "S"(a2), "d"(a3) : "rcx","r11","memory");
    return r;
}
static inline long sc6(long n, long a1, long a2, long a3, long a4, long a5, long a6) {
    long r;
    register long r10 __asm__("r10") = a4;
    register long r8  __asm__("r8")  = a5;
    register long r9  __asm__("r9")  = a6;
    __asm__ volatile("syscall"
        : "=a"(r)
        : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8), "r"(r9)
        : "rcx","r11","memory");
    return r;
}

static usize cstrlen(const char *s) {
    usize n = 0;
    while (s[n]) n++;
    return n;
}
static void write_str(int fd, const char *s) {
    sc3(SYS_write, fd, (long)s, (long)cstrlen(s));
}
static void die(const char *s) {
    write_str(2, s);
    sc1(SYS_exit, 1);
    for (;;){}
}

static int dev_open(void) {
    return (int)sc3(SYS_open, (long)DEV_PATH, O_RDWR, 0);
}
static void dev_close(int fd) {
    sc1(SYS_close, fd);
}
static void *xmap(usize len) {
    long p = sc6(SYS_mmap, 0, len, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (p < 0) die("mmap fail\n");
    return (void *)p;
}

static u32 get_u32(int fd, u32 req) {
    u32 v = 0;
    if (sc3(SYS_ioctl, fd, req, (long)&v) < 0) die("ioctl fail\n");
    return v;
}
static void reset_dev(int fd) {
    if (sc3(SYS_ioctl, fd, IOCTL_RESET, 0) < 0) die("reset fail\n");
}
static void move_dev(int fd, u32 dir) {
    u32 v = dir;
    if (sc3(SYS_ioctl, fd, IOCTL_MOVE, (long)&v) < 0) die("move fail\n");
}
static void get_flag(int fd, char out[64]) {
    if (sc3(SYS_ioctl, fd, IOCTL_GET_FLAG, (long)out) < 0) die("flag fail\n");
}

static u64 hash_pos(s32 x, s32 y, s32 z) {
    u64 h = (u32)x * 0x9e3779b1u;
    h ^= ((u64)(u32)y * 0x85ebca77u) << 1;
    h ^= ((u64)(u32)z * 0xc2b2ae3du) << 7;
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdULL;
    h ^= h >> 33;
    h *= 0xc4ceb9fe1a85ec53ULL;
    h ^= h >> 33;
    return h;
}
static usize next_pow2(usize x) {
    usize p = 1;
    while (p < x) p <<= 1;
    return p;
}

static int seen_has(struct Slot *tab, usize cap, s32 x, s32 y, s32 z) {
    usize m = cap - 1;
    usize i = (usize)hash_pos(x, y, z) & m;
    for (;;) {
        if (!tab[i].used) return 0;
        if (tab[i].x == x && tab[i].y == y && tab[i].z == z) return 1;
        i = (i + 1) & m;
    }
}
static void seen_put(struct Slot *tab, usize cap, s32 x, s32 y, s32 z) {
    usize m = cap - 1;
    usize i = (usize)hash_pos(x, y, z) & m;
    for (;;) {
        if (!tab[i].used) {
            tab[i].used = 1;
            tab[i].x = x;
            tab[i].y = y;
            tab[i].z = z;
            return;
        }
        if (tab[i].x == x && tab[i].y == y && tab[i].z == z) return;
        i = (i + 1) & m;
    }
}

static u32 replay(int fd, struct Frame *st, usize sp) {
    usize i;
    u32 s;
    reset_dev(fd);
    for (i = 1; i < sp; i++) {
        move_dev(fd, (u32)(u8)st[i].incoming);
        s = get_u32(fd, IOCTL_GET_STATUS);
        if (s != ROOM_NORMAL && s != ROOM_GOAL) die("replay bad\n");
    }
    return get_u32(fd, IOCTL_GET_STATUS);
}

static void write_flag_line(char *buf) {
    usize n = 0;
    while (n < 64 && buf[n]) n++;
    sc3(SYS_write, 1, (long)buf, n);
    sc3(SYS_write, 1, (long)"\n", 1);
}

static int main_c(void) {
    int fd = dev_open();
    if (fd < 0) die("open fail\n");

    u64 dx = get_u32(fd, IOCTL_GET_X);
    u64 dy = get_u32(fd, IOCTL_GET_Y);
    u64 dz = get_u32(fd, IOCTL_GET_Z);

    u64 total = dx * dy * dz;
    if (total < 16) total = 16;
    if (total > (1ULL << 22)) total = (1ULL << 22);

    usize seen_cap = next_pow2((usize)(total * 2));
    struct Slot *seen = (struct Slot *)xmap(seen_cap * sizeof(struct Slot));
    struct Frame *stack = (struct Frame *)xmap((usize)total * sizeof(struct Frame));
    usize sp = 0;
    u32 s;

    reset_dev(fd);
    s = get_u32(fd, IOCTL_GET_STATUS);

    if (s == ROOM_GOAL) {
        char flag[64];
        get_flag(fd, flag);
        write_flag_line(flag);
        dev_close(fd);
        return 0;
    }
    if (s != ROOM_NORMAL) die("bad start\n");

    seen_put(seen, seen_cap, 0, 0, 0);
    stack[0].x = 0;
    stack[0].y = 0;
    stack[0].z = 0;
    stack[0].exits = get_u32(fd, IOCTL_GET_EXITS);
    stack[0].next_dir = 0;
    stack[0].incoming = -1;
    sp = 1;

    while (sp) {
        struct Frame *cur = &stack[sp - 1];
        int advanced = 0;

        while (cur->next_dir < 6) {
            u8 dir = cur->next_dir++;
            if (((cur->exits >> dir) & 1u) == 0) continue;

            s32 nx = cur->x + DX[dir];
            s32 ny = cur->y + DY[dir];
            s32 nz = cur->z + DZ[dir];

            if (seen_has(seen, seen_cap, nx, ny, nz)) continue;

            move_dev(fd, dir);
            s = get_u32(fd, IOCTL_GET_STATUS);
            seen_put(seen, seen_cap, nx, ny, nz);

            if (s == ROOM_GOAL) {
                char flag[64];
                get_flag(fd, flag);
                write_flag_line(flag);
                dev_close(fd);
                return 0;
            }

            if (s == ROOM_NORMAL) {
                stack[sp].x = nx;
                stack[sp].y = ny;
                stack[sp].z = nz;
                stack[sp].exits = get_u32(fd, IOCTL_GET_EXITS);
                stack[sp].next_dir = 0;
                stack[sp].incoming = (signed char)dir;
                sp++;
                advanced = 1;
                break;
            }

            if (s == ROOM_TRAP) {
                if (replay(fd, stack, sp) != ROOM_NORMAL) die("trap recover\n");
                continue;
            }

            die("unknown status\n");
        }

        if (advanced) continue;
        if (sp == 1) break;

        u8 back = OPP[(u8)cur->incoming];
        sp--;

        move_dev(fd, back);
        s = get_u32(fd, IOCTL_GET_STATUS);
        if (s != ROOM_NORMAL) {
            if (replay(fd, stack, sp) != ROOM_NORMAL) die("backtrack recover\n");
        }
    }

    die("not found\n");
    return 1;
}

void _start(void) {
    int rc = main_c();
    sc1(SYS_exit, rc);
}