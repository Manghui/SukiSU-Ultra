#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/kfifo.h>

#include "klog.h"
#include "sulog.h"
#include "ksu.h"

#if __SULOG_GATE

#define SULOG_FIFO_SIZE (64 * sizeof(struct sulog_entry *))

struct dedup_entry dedup_tbl[SULOG_COMM_LEN];
DEFINE_SPINLOCK(dedup_lock);

static DECLARE_KFIFO(sulog_fifo, struct sulog_entry *, 64);
static DEFINE_SPINLOCK(fifo_lock);
static struct workqueue_struct *sulog_workqueue;
static struct work_struct sulog_work;
static bool sulog_enabled = true;
static atomic_t pending_work = ATOMIC_INIT(0);

static void get_timestamp(char *buf, size_t len)
{
    struct timespec64 ts;
    struct tm tm;
    time64_t local_time;

    ktime_get_real_ts64(&ts);
    local_time = ts.tv_sec - (sys_tz.tz_minuteswest * 60);
    time64_to_tm(local_time, 0, &tm);

    snprintf(buf, len, "%04ld-%02d-%02d %02d:%02d:%02d",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec);
}

static void ksu_get_cmdline(char *full_comm, const char *comm, size_t buf_len)
{
    char *kbuf;
    int n;

    if (!full_comm || buf_len <= 0)
        return;

    if (comm && strlen(comm) > 0) {
        ksu_strlcpy(full_comm, comm, buf_len);
        return;
    }

    kbuf = kmalloc(buf_len, GFP_ATOMIC);
    if (!kbuf) {
        pr_err("sulog: failed to allocate memory for kbuf\n");
        return;
    }

    n = get_cmdline(current, kbuf, buf_len);
    if (n <= 0) {
        ksu_strlcpy(full_comm, current->comm, buf_len);
    } else {
        for (int i = 0; i < n; i++) {
            if (kbuf[i] == '\0')
                kbuf[i] = ' ';
        }
        kbuf[n < buf_len ? n : buf_len - 1] = '\0';
        ksu_strlcpy(full_comm, kbuf, buf_len);
    }

    kfree(kbuf);
}

static bool dedup_should_print(uid_t uid, u8 type, const char *content, size_t len)
{
    struct dedup_key key = {
        .crc = dedup_calc_hash(content, len),
        .uid = uid,
        .type = type,
    };
    u64 now = ktime_get_ns();
    u64 delta_ns = DEDUP_SECS * NSEC_PER_SEC;
    u32 idx = key.crc & (SULOG_COMM_LEN - 1);
    struct dedup_entry *e;
    bool should_print;

    spin_lock(&dedup_lock);
    e = &dedup_tbl[idx];
    should_print = !(e->key.crc == key.crc && e->key.uid == key.uid &&
                     e->key.type == key.type && (now - e->ts_ns) < delta_ns);
    if (should_print) {
        e->key = key;
        e->ts_ns = now;
    }
    spin_unlock(&dedup_lock);

    return should_print;
}

static void sulog_work_handler(struct work_struct *work)
{
    struct file *fp;
    struct sulog_entry *entry;
    loff_t pos = 0;
    unsigned int entries_processed = 0;
    unsigned long flags;

    fp = filp_open(SULOG_PATH, O_WRONLY | O_CREAT | O_APPEND, 0640);
    if (IS_ERR(fp)) {
        pr_err("sulog: failed to open log file: %ld\n", PTR_ERR(fp));
        goto clear_pending;
    }

    if (fp->f_inode->i_size > SULOG_MAX_SIZE) {
        pr_info("sulog: log file exceeds maximum size, clearing...\n");
        if (vfs_truncate(&fp->f_path, 0))
            pr_err("sulog: failed to truncate log file\n");
        pos = 0;
    } else {
        pos = fp->f_inode->i_size;
    }

    spin_lock_irqsave(&fifo_lock, flags);
    while (kfifo_out(&sulog_fifo, &entry, 1)) {
        spin_unlock_irqrestore(&fifo_lock, flags);

        if (entry) {
            kernel_write(fp, entry->content, strlen(entry->content), &pos);
            kfree(entry);
            entries_processed++;
        }

        spin_lock_irqsave(&fifo_lock, flags);
    }
    spin_unlock_irqrestore(&fifo_lock, flags);

    vfs_fsync(fp, 0);
    filp_close(fp, 0);

    if (entries_processed > 0)
        pr_debug("sulog: wrote %u entries\n", entries_processed);

clear_pending:
    atomic_set(&pending_work, 0);
}

static bool sulog_add_entry(struct sulog_entry *entry)
{
    unsigned long flags;
    bool queued;
    int should_queue;

    if (!sulog_enabled || !entry)
        return false;

    spin_lock_irqsave(&fifo_lock, flags);
    queued = kfifo_in(&sulog_fifo, &entry, 1) > 0;
    should_queue = !atomic_cmpxchg(&pending_work, 0, 1);
    spin_unlock_irqrestore(&fifo_lock, flags);

    if (queued && should_queue && sulog_workqueue)
        queue_work(sulog_workqueue, &sulog_work);

    if (!queued) {
        pr_warn("sulog: fifo full, dropping entry\n");
        kfree(entry);
    }

    return queued;
}

static struct sulog_entry *sulog_alloc_entry(const char *log_buf)
{
    struct sulog_entry *entry;

    entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
    if (!entry) {
        pr_err("sulog: failed to allocate log entry\n");
        return NULL;
    }

    ksu_strlcpy(entry->content, log_buf, SULOG_ENTRY_MAX_LEN - 1);

    return entry;
}

void ksu_sulog_report_su_grant(uid_t uid, const char *comm, const char *method)
{
    char timestamp[32];
    char full_comm[SULOG_COMM_LEN];
    char log_buf[SULOG_ENTRY_MAX_LEN];
    struct sulog_entry *entry;

    if (!sulog_enabled)
        return;

    get_timestamp(timestamp, sizeof(timestamp));
    ksu_get_cmdline(full_comm, comm, sizeof(full_comm));

    snprintf(log_buf, sizeof(log_buf),
             "[%s] SU_GRANT: UID=%d COMM=%s METHOD=%s PID=%d\n",
             timestamp, uid, full_comm, method ? method : "unknown",
             current->pid);

    if (!dedup_should_print(uid, DEDUP_SU_GRANT, log_buf, strlen(log_buf)))
        return;

    entry = sulog_alloc_entry(log_buf);
    if (entry)
        sulog_add_entry(entry);
}

void ksu_sulog_report_su_attempt(uid_t uid, const char *comm,
                                 const char *target_path, bool success)
{
    char timestamp[32];
    char full_comm[SULOG_COMM_LEN];
    char log_buf[SULOG_ENTRY_MAX_LEN];
    struct sulog_entry *entry;

    if (!sulog_enabled)
        return;

    get_timestamp(timestamp, sizeof(timestamp));
    ksu_get_cmdline(full_comm, comm, sizeof(full_comm));

    snprintf(log_buf, sizeof(log_buf),
             "[%s] SU_EXEC: UID=%d COMM=%s TARGET=%s RESULT=%s PID=%d\n",
             timestamp, uid, full_comm, target_path ? target_path : "unknown",
             success ? "SUCCESS" : "DENIED", current->pid);

    if (!dedup_should_print(uid, DEDUP_SU_ATTEMPT, log_buf, strlen(log_buf)))
        return;

    entry = sulog_alloc_entry(log_buf);
    if (entry)
        sulog_add_entry(entry);
}

void ksu_sulog_report_permission_check(uid_t uid, const char *comm, bool allowed)
{
    char timestamp[32];
    char full_comm[SULOG_COMM_LEN];
    char log_buf[SULOG_ENTRY_MAX_LEN];
    struct sulog_entry *entry;

    if (!sulog_enabled)
        return;

    get_timestamp(timestamp, sizeof(timestamp));
    ksu_get_cmdline(full_comm, comm, sizeof(full_comm));

    snprintf(log_buf, sizeof(log_buf),
             "[%s] PERM_CHECK: UID=%d COMM=%s RESULT=%s PID=%d\n",
             timestamp, uid, full_comm, allowed ? "ALLOWED" : "DENIED",
             current->pid);

    if (!dedup_should_print(uid, DEDUP_PERM_CHECK, log_buf, strlen(log_buf)))
        return;

    entry = sulog_alloc_entry(log_buf);
    if (entry)
        sulog_add_entry(entry);
}

void ksu_sulog_report_manager_operation(const char *operation, uid_t manager_uid,
                                        uid_t target_uid)
{
    char timestamp[32];
    char full_comm[SULOG_COMM_LEN];
    char log_buf[SULOG_ENTRY_MAX_LEN];
    struct sulog_entry *entry;

    if (!sulog_enabled)
        return;

    get_timestamp(timestamp, sizeof(timestamp));
    ksu_get_cmdline(full_comm, NULL, sizeof(full_comm));

    snprintf(log_buf, sizeof(log_buf),
             "[%s] MANAGER_OP: OP=%s MANAGER_UID=%d TARGET_UID=%d COMM=%s PID=%d\n",
             timestamp, operation ? operation : "unknown", manager_uid, target_uid,
             full_comm, current->pid);

    if (!dedup_should_print(manager_uid, DEDUP_MANAGER_OP, log_buf, strlen(log_buf)))
        return;

    entry = sulog_alloc_entry(log_buf);
    if (entry)
        sulog_add_entry(entry);
}

void ksu_sulog_report_syscall(uid_t uid, const char *comm, const char *syscall,
                              const char *args)
{
    char timestamp[32];
    char full_comm[SULOG_COMM_LEN];
    char log_buf[SULOG_ENTRY_MAX_LEN];
    struct sulog_entry *entry;

    if (!sulog_enabled)
        return;

    get_timestamp(timestamp, sizeof(timestamp));
    ksu_get_cmdline(full_comm, comm, sizeof(full_comm));

    snprintf(log_buf, sizeof(log_buf),
             "[%s] SYSCALL: UID=%d COMM=%s SYSCALL=%s ARGS=%s PID=%d\n",
             timestamp, uid, full_comm, syscall ? syscall : "unknown",
             args ? args : "none", current->pid);

    if (!dedup_should_print(uid, DEDUP_SYSCALL, log_buf, strlen(log_buf)))
        return;

    entry = sulog_alloc_entry(log_buf);
    if (entry)
        sulog_add_entry(entry);
}

int ksu_sulog_init(void)
{
    sulog_workqueue = alloc_workqueue("ksu_sulog", WQ_UNBOUND | WQ_HIGHPRI, 1);
    if (!sulog_workqueue) {
        pr_err("sulog: failed to create workqueue\n");
        return -ENOMEM;
    }

    INIT_WORK(&sulog_work, sulog_work_handler);
    pr_info("sulog: initialized successfully\n");

    return 0;
}

void ksu_sulog_exit(void)
{
    struct sulog_entry *entry;
    unsigned long flags;

    sulog_enabled = false;

    if (sulog_workqueue) {
        flush_workqueue(sulog_workqueue);
        destroy_workqueue(sulog_workqueue);
        sulog_workqueue = NULL;
    }

    spin_lock_irqsave(&fifo_lock, flags);
    while (kfifo_out(&sulog_fifo, &entry, 1)) {
        if (entry)
            kfree(entry);
    }
    spin_unlock_irqrestore(&fifo_lock, flags);

    pr_info("sulog: cleaned up successfully\n");
}

#endif
