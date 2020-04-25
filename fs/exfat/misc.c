// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *  Copyright (C) 2012-2013 Samsung Electronics Co., Ltd.
 *
 *  misc.c: Helper function for checksum and handling exFAT errors
 */

/*
 *  linux/fs/fat/misc.c
 *
 *  Written 1992,1993 by Werner Almesberger
 *  22/11/2000 - Fixed fat_date_unix2dos for dates earlier than 01/01/1980
 *		 and date_dos2unix for date==0 by Igor Zhbanov(bsg@uniyar.ac.ru)
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/buffer_head.h>
#include <linux/time.h>
#include "exfat.h"
#include "version.h"

#ifdef CONFIG_EXFAT_UEVENT
static struct kobject exfat_uevent_kobj;

int exfat_uevent_init(struct kset *exfat_kset)
{
	int err;
	struct kobj_type *ktype = get_ktype(&exfat_kset->kobj);

	exfat_uevent_kobj.kset = exfat_kset;
	err = kobject_init_and_add(&exfat_uevent_kobj, ktype, NULL, "uevent");
	if (err)
		pr_err("[EXFAT] Unable to create exfat uevent kobj\n");

	return err;
}

void exfat_uevent_uninit(void)
{
	kobject_del(&exfat_uevent_kobj);
	memset(&exfat_uevent_kobj, 0, sizeof(struct kobject));
}

void exfat_uevent_ro_remount(struct super_block *sb)
{
	struct block_device *bdev = sb->s_bdev;
	dev_t bd_dev = bdev ? bdev->bd_dev : 0;

	char major[16], minor[16];
	char *envp[] = { major, minor, NULL };

	snprintf(major, sizeof(major), "MAJOR=%d", MAJOR(bd_dev));
	snprintf(minor, sizeof(minor), "MINOR=%d", MINOR(bd_dev));

	kobject_uevent_env(&exfat_uevent_kobj, KOBJ_CHANGE, envp);
}
#endif

/*
 * exfat_fs_error reports a file system problem that might indicate fa data
 * corruption/inconsistency. Depending on 'errors' mount option the
 * panic() is called, or error message is printed FAT and nothing is done,
 * or filesystem is remounted read-only (default behavior).
 * In case the file system is remounted read-only, it can be made writable
 * again by remounting it.
 */
void __exfat_fs_error(struct super_block *sb, int report, const char *fmt, ...)
{
	struct exfat_mount_options *opts = &EXFAT_SB(sb)->options;
	va_list args;
	struct va_format vaf;
	struct block_device *bdev = sb->s_bdev;
	dev_t bd_dev = bdev ? bdev->bd_dev : 0;

	if (report) {
		va_start(args, fmt);
		vaf.fmt = fmt;
		vaf.va = &args;
		pr_err("exFAT-fs (%s[%d:%d]): ERR: %pV\n",
			sb->s_id, MAJOR(bd_dev), MINOR(bd_dev), &vaf);
		va_end(args);
	}

	if (opts->errors == EXFAT_ERRORS_PANIC) {
		panic("exFAT-fs (%s[%d:%d]): fs panic from previous error\n",
			sb->s_id, MAJOR(bd_dev), MINOR(bd_dev));
	} else if (opts->errors == EXFAT_ERRORS_RO && !EXFAT_IS_SB_RDONLY(sb)) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 14, 0)
		sb->s_flags |= MS_RDONLY;
#else
		sb->s_flags |= SB_RDONLY;
#endif
		pr_err("exFAT-fs (%s[%d:%d]): file-system has been set to "
			"read-only\n", sb->s_id, MAJOR(bd_dev), MINOR(bd_dev));
		exfat_uevent_ro_remount(sb);
	}
}
EXPORT_SYMBOL(__exfat_fs_error);

/**
 * __exfat_msg() - print preformated EXFAT specific messages.
 * All logs except what uses exfat_fs_error() should be written by __exfat_msg()
 */
void __exfat_msg(struct super_block *sb, const char *level, int st, const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;
	struct block_device *bdev = sb->s_bdev;
	dev_t bd_dev = bdev ? bdev->bd_dev : 0;

	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;
	/* level means KERN_ pacility level */
	printk("%sexFAT-fs (%s[%d:%d]): %pV\n", level,
			sb->s_id, MAJOR(bd_dev), MINOR(bd_dev), &vaf);
	va_end(args);
}
EXPORT_SYMBOL(__exfat_msg);

void exfat_log_version(void)
{
	pr_info("exFAT: file-system version %s\n", EXFAT_VERSION);
}
EXPORT_SYMBOL(exfat_log_version);

/* <linux/time.h> externs sys_tz
 * extern struct timezone sys_tz;
 */
#define UNIX_SECS_1980    315532800L

#if BITS_PER_LONG == 64
#define UNIX_SECS_2108    4354819200L
#endif

/* days between 1970/01/01 and 1980/01/01 (2 leap days) */
#define DAYS_DELTA_DECADE    (365 * 10 + 2)
/* 120 (2100 - 1980) isn't leap year */
#define NO_LEAP_YEAR_2100    (120)
#define IS_LEAP_YEAR(y)    (!((y) & 0x3) && (y) != NO_LEAP_YEAR_2100)

#define SECS_PER_MIN    (60)
#define SECS_PER_HOUR   (60 * SECS_PER_MIN)
#define SECS_PER_DAY    (24 * SECS_PER_HOUR)

#define MAKE_LEAP_YEAR(leap_year, year)                         \
	do {                                                    \
		/* 2100 isn't leap year */                      \
		if (unlikely(year > NO_LEAP_YEAR_2100))         \
			leap_year = ((year + 3) / 4) - 1;       \
		else                                            \
			leap_year = ((year + 3) / 4);           \
	} while (0)

/* Linear day numbers of the respective 1sts in non-leap years. */
static ktime_t accum_days_in_year[] = {
	/* Month : N 01  02  03  04  05  06  07  08  09  10  11  12 */
	0, 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 0, 0, 0,
};

/* Convert a FAT time/date pair to a UNIX date (seconds since 1 1 70). */
void exfat_time_fat2unix(struct exfat_sb_info *sbi, struct timespec_compat *ts,
		DATE_TIME_T *tp)
{
	ktime_t year = tp->Year;
	ktime_t ld; /* leap day */

	MAKE_LEAP_YEAR(ld, year);

	if (IS_LEAP_YEAR(year) && (tp->Month) > 2)
		ld++;

	ts->tv_sec =  tp->Second  + tp->Minute * SECS_PER_MIN
			+ tp->Hour * SECS_PER_HOUR
			+ (year * 365 + ld + accum_days_in_year[tp->Month]
			+ (tp->Day - 1) + DAYS_DELTA_DECADE) * SECS_PER_DAY;

	if (!sbi->options.tz_utc)
		ts->tv_sec += sys_tz.tz_minuteswest * SECS_PER_MIN;

	ts->tv_nsec = 0;
}

/* Convert linear UNIX date to a FAT time/date pair. */
void exfat_time_unix2fat(struct exfat_sb_info *sbi, struct timespec_compat *ts,
		DATE_TIME_T *tp)
{
	ktime_t second = ts->tv_sec;
	ktime_t day, month, year;
	ktime_t ld; /* leap day */

	if (!sbi->options.tz_utc)
		second -= sys_tz.tz_minuteswest * SECS_PER_MIN;

	/* Jan 1 GMT 00:00:00 1980. But what about another time zone? */
	if (second < UNIX_SECS_1980) {
		tp->Second  = 0;
		tp->Minute  = 0;
		tp->Hour = 0;
		tp->Day  = 1;
		tp->Month  = 1;
		tp->Year = 0;
		return;
	}
#if (BITS_PER_LONG == 64)
	if (second >= UNIX_SECS_2108) {
		tp->Second  = 59;
		tp->Minute  = 59;
		tp->Hour = 23;
		tp->Day  = 31;
		tp->Month  = 12;
		tp->Year = 127;
		return;
	}
#endif

	day = second / SECS_PER_DAY - DAYS_DELTA_DECADE;
	year = day / 365;

	MAKE_LEAP_YEAR(ld, year);
	if (year * 365 + ld > day)
		year--;

	MAKE_LEAP_YEAR(ld, year);
	day -= year * 365 + ld;

	if (IS_LEAP_YEAR(year) && day == accum_days_in_year[3]) {
		month = 2;
	} else {
		if (IS_LEAP_YEAR(year) && day > accum_days_in_year[3])
			day--;
		for (month = 1; month < 12; month++) {
			if (accum_days_in_year[month + 1] > day)
				break;
		}
	}
	day -= accum_days_in_year[month];

	tp->Second  = second % SECS_PER_MIN;
	tp->Minute  = (second / SECS_PER_MIN) % 60;
	tp->Hour = (second / SECS_PER_HOUR) % 24;
	tp->Day  = day + 1;
	tp->Month  = month;
	tp->Year = year;
}

TIMESTAMP_T *exfat_tm_now(struct exfat_sb_info *sbi, TIMESTAMP_T *tp)
{
	struct timespec_compat ts;
	DATE_TIME_T dt;

	KTIME_GET_REAL_TS(&ts);
	exfat_time_unix2fat(sbi, &ts, &dt);

	tp->year = dt.Year;
	tp->mon = dt.Month;
	tp->day = dt.Day;
	tp->hour = dt.Hour;
	tp->min = dt.Minute;
	tp->sec = dt.Second;

	return tp;
}

u16 exfat_calc_chksum_2byte(void *data, s32 len, u16 chksum, s32 type)
{
	s32 i;
	u8 *c = (u8 *) data;

	for (i = 0; i < len; i++, c++) {
		if (((i == 2) || (i == 3)) && (type == CS_DIR_ENTRY))
			continue;
		chksum = (((chksum & 1) << 15) | ((chksum & 0xFFFE) >> 1)) + (u16) *c;
	}
	return chksum;
}

#ifdef CONFIG_EXFAT_DBG_MSG
void __exfat_dmsg(int level, const char *fmt, ...)
{
	va_list args;

	/* should check type */
	if (level > EXFAT_MSG_LEVEL)
		return;

	va_start(args, fmt);
	/* fmt already includes KERN_ pacility level */
	vprintk(fmt, args);
	va_end(args);
}
#endif

#if BITS_PER_LONG == 32
/*
 * Support 64/64 => 64 division on a 32-bit platform.  While the kernel
 * provides a div64_u64() function for this we do not use it because the
 * implementation is flawed.  There are cases which return incorrect
 * results as late as linux-2.6.35.  Until this is fixed upstream the
 * spl must provide its own implementation.
 *
 * This implementation is a slightly modified version of the algorithm
 * proposed by the book 'Hacker's Delight'.  The original source can be
 * found here and is available for use without restriction.
 *
 * http://www.hackersdelight.org/HDcode/newCode/divDouble.c
 */

/*
 * Calculate number of leading of zeros for a 64-bit value.
 */
static int
nlz64(uint64_t x)
{
	register int n = 0;

	if (x == 0)
		return (64);

	if (x <= 0x00000000FFFFFFFFULL) { n = n + 32; x = x << 32; }
	if (x <= 0x0000FFFFFFFFFFFFULL) { n = n + 16; x = x << 16; }
	if (x <= 0x00FFFFFFFFFFFFFFULL) { n = n +  8; x = x <<  8; }
	if (x <= 0x0FFFFFFFFFFFFFFFULL) { n = n +  4; x = x <<  4; }
	if (x <= 0x3FFFFFFFFFFFFFFFULL) { n = n +  2; x = x <<  2; }
	if (x <= 0x7FFFFFFFFFFFFFFFULL) { n = n +  1; }

	return (n);
}

/*
 * Newer kernels have a div_u64() function but we define our own
 * to simplify portability between kernel versions.
 */
static inline uint64_t
__div_u64(uint64_t u, uint32_t v)
{
	(void) do_div(u, v);
	return (u);
}

/*
 * Implementation of 64-bit unsigned division for 32-bit machines.
 *
 * First the procedure takes care of the case in which the divisor is a
 * 32-bit quantity. There are two subcases: (1) If the left half of the
 * dividend is less than the divisor, one execution of do_div() is all that
 * is required (overflow is not possible). (2) Otherwise it does two
 * divisions, using the grade school method.
 */
uint64_t
__udivdi3(uint64_t u, uint64_t v)
{
	uint64_t u0, u1, v1, q0, q1, k;
	int n;

	if (v >> 32 == 0) {			// If v < 2**32:
		if (u >> 32 < v) {		// If u/v cannot overflow,
			return (__div_u64(u, v)); // just do one division.
		} else {			// If u/v would overflow:
			u1 = u >> 32;		// Break u into two halves.
			u0 = u & 0xFFFFFFFF;
			q1 = __div_u64(u1, v);	// First quotient digit.
			k  = u1 - q1 * v;	// First remainder, < v.
			u0 += (k << 32);
			q0 = __div_u64(u0, v);	// Seconds quotient digit.
			return ((q1 << 32) + q0);
		}
	} else {				// If v >= 2**32:
		n = nlz64(v);			// 0 <= n <= 31.
		v1 = (v << n) >> 32;		// Normalize divisor, MSB is 1.
		u1 = u >> 1;			// To ensure no overflow.
		q1 = __div_u64(u1, v1);		// Get quotient from
		q0 = (q1 << n) >> 31;		// Undo normalization and
						// division of u by 2.
		if (q0 != 0)			// Make q0 correct or
			q0 = q0 - 1;		// too small by 1.
		if ((u - q0 * v) >= v)
			q0 = q0 + 1;		// Now q0 is correct.

		return (q0);
	}
}
EXPORT_SYMBOL(__udivdi3);

/* BEGIN CSTYLED */
#ifndef abs64
#define	abs64(x)	({ uint64_t t = (x) >> 63; ((x) ^ t) - t; })
#endif
/* END CSTYLED */

/*
 * Implementation of 64-bit signed division for 32-bit machines.
 */
int64_t
__divdi3(int64_t u, int64_t v)
{
	int64_t q, t;
	// cppcheck-suppress shiftTooManyBitsSigned
	q = __udivdi3(abs64(u), abs64(v));
	// cppcheck-suppress shiftTooManyBitsSigned
	t = (u ^ v) >> 63;	// If u, v have different
	return ((q ^ t) - t);	// signs, negate q.
}
EXPORT_SYMBOL(__divdi3);

/*
 * Implementation of 64-bit unsigned modulo for 32-bit machines.
 */
uint64_t
__umoddi3(uint64_t dividend, uint64_t divisor)
{
	return (dividend - (divisor * __udivdi3(dividend, divisor)));
}
EXPORT_SYMBOL(__umoddi3);

/*
 * Implementation of 64-bit unsigned division/modulo for 32-bit machines.
 */
uint64_t
__udivmoddi4(uint64_t n, uint64_t d, uint64_t *r)
{
	uint64_t q = __udivdi3(n, d);
	if (r)
		*r = n - d * q;
	return (q);
}
EXPORT_SYMBOL(__udivmoddi4);

/*
 * Implementation of 64-bit signed division/modulo for 32-bit machines.
 */
/*
int64_t
__divmoddi4(int64_t n, int64_t d, int64_t *r)
{
	int64_t q, rr;
	boolean_t nn = B_FALSE;
	boolean_t nd = B_FALSE;
	if (n < 0) {
		nn = B_TRUE;
		n = -n;
	}
	if (d < 0) {
		nd = B_TRUE;
		d = -d;
	}

	q = __udivmoddi4(n, d, (uint64_t *)&rr);

	if (nn != nd)
		q = -q;
	if (nn)
		rr = -rr;
	if (r)
		*r = rr;
	return (q);
}
EXPORT_SYMBOL(__divmoddi4);
*/

#if defined(__arm) || defined(__arm__)
/*
 * Implementation of 64-bit (un)signed division for 32-bit arm machines.
 *
 * Run-time ABI for the ARM Architecture (page 20).  A pair of (unsigned)
 * long longs is returned in {{r0, r1}, {r2,r3}}, the quotient in {r0, r1},
 * and the remainder in {r2, r3}.  The return type is specifically left
 * set to 'void' to ensure the compiler does not overwrite these registers
 * during the return.  All results are in registers as per ABI
 */
void
__aeabi_uldivmod(uint64_t u, uint64_t v)
{
	uint64_t res;
	uint64_t mod;

	res = __udivdi3(u, v);
	mod = __umoddi3(u, v);
	{
		register uint32_t r0 asm("r0") = (res & 0xFFFFFFFF);
		register uint32_t r1 asm("r1") = (res >> 32);
		register uint32_t r2 asm("r2") = (mod & 0xFFFFFFFF);
		register uint32_t r3 asm("r3") = (mod >> 32);

		/* BEGIN CSTYLED */
		asm volatile(""
		    : "+r"(r0), "+r"(r1), "+r"(r2),"+r"(r3)  /* output */
		    : "r"(r0), "r"(r1), "r"(r2), "r"(r3));   /* input */
		/* END CSTYLED */

		return; /* r0; */
	}
}
EXPORT_SYMBOL(__aeabi_uldivmod);

void
__aeabi_ldivmod(int64_t u, int64_t v)
{
	int64_t res;
	uint64_t mod;

	res =  __divdi3(u, v);
	mod = __umoddi3(u, v);
	{
		register uint32_t r0 asm("r0") = (res & 0xFFFFFFFF);
		register uint32_t r1 asm("r1") = (res >> 32);
		register uint32_t r2 asm("r2") = (mod & 0xFFFFFFFF);
		register uint32_t r3 asm("r3") = (mod >> 32);

		/* BEGIN CSTYLED */
		asm volatile(""
		    : "+r"(r0), "+r"(r1), "+r"(r2),"+r"(r3)  /* output */
		    : "r"(r0), "r"(r1), "r"(r2), "r"(r3));   /* input */
		/* END CSTYLED */

		return; /* r0; */
	}
}
EXPORT_SYMBOL(__aeabi_ldivmod);
#endif /* __arm || __arm__ */
#endif /* BITS_PER_LONG */
