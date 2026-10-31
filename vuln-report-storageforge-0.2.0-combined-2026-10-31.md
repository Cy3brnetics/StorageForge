# Vulnerability Scan Report

**Image:** `storageforge:0.2.0`

---

# Grype (Anchore)

**Duration:** 142.2s

## Summary

**5 Critical** | **84 High** | 96 Medium | 18 Low | 98 Negligible

**Total:** 301 vulnerabilities

## Critical (5)

### CVE-2026-5450

- **Package:** `libc-bin`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-5450](https://security-tracker.debian.org/tracker/CVE-2026-5450)

Calling the scanf family of functions with a %mc (malloc'd character match) in the GNU C Library version 2.7 to version 2.43 with a format width specifier with an explicit width greater than 1024 could result in a one byte heap buffer overflow.

### CVE-2026-5450

- **Package:** `libc6`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-5450](https://security-tracker.debian.org/tracker/CVE-2026-5450)

Calling the scanf family of functions with a %mc (malloc'd character match) in the GNU C Library version 2.7 to version 2.43 with a format width specifier with an explicit width greater than 1024 could result in a one byte heap buffer overflow.

### CVE-2025-7458

- **Package:** `libsqlite3-0`
- **Installed:** `3.40.1-2+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-7458](https://security-tracker.debian.org/tracker/CVE-2025-7458)

An integer overflow in the sqlite3KeyInfoFromExprList function in SQLite versions 3.39.2 through 3.41.1 allows an attacker with the ability to execute arbitrary SQL statements to cause a denial of service or disclose sensitive information from process memory via a crafted SELECT statement with a large number of expressions in the ORDER BY clause.

### CVE-2025-7458

- **Package:** `sqlite3`
- **Installed:** `3.40.1-2+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-7458](https://security-tracker.debian.org/tracker/CVE-2025-7458)

An integer overflow in the sqlite3KeyInfoFromExprList function in SQLite versions 3.39.2 through 3.41.1 allows an attacker with the ability to execute arbitrary SQL statements to cause a denial of service or disclose sensitive information from process memory via a crafted SELECT statement with a large number of expressions in the ORDER BY clause.

### CVE-2026-60002

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-60002](https://security-tracker.debian.org/tracker/CVE-2026-60002)

ssh in OpenSSH before 10.4 can have a use-after-free when a server changes its host key during a key re-exchange. (This outcome occurs only on the client side.)

## High (84)

### CVE-2025-13151

- **Package:** `libtasn1-6`
- **Installed:** `4.19.0-2+deb12u1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-13151](https://security-tracker.debian.org/tracker/CVE-2025-13151)

Stack-based buffer overflow in libtasn1 version: v4.20.0. The function fails to validate the size of input data resulting in a buffer overflow in asn1_expend_octet_string.

### CVE-2026-82560

- **Package:** `perl-base`
- **Installed:** `5.36.0-7+deb12u4`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-82560](https://security-tracker.debian.org/tracker/CVE-2026-82560)

Pod::Text versions before 6.1.1 for Perl allow CPU and memory exhaustion formatting a POD document whose =over nesting drives the margin to the output width.  Each =over adds its indent to the margin, which wrap() subtracts from the output width to get the space available for text. When that space reaches zero, the line-splitting substitution matches the empty string, and the loop consumes no input while appending the margin padding on every pass.  Formatting an attacker-supplied POD document never returns, and the output grows until memory is exhausted.

### CVE-2026-41992

- **Package:** `gzip`
- **Installed:** `1.12-1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-41992](https://security-tracker.debian.org/tracker/CVE-2026-41992)

GNU gzip contains a global buffer overflow vulnerability in the LZH decompression logic caused by improper reuse of shared global state between different decompression formats within a single execution. GNU gzip maintains a global array that is shared across the LZ77, LZW, and LZH decompression routines and is not reinitialized between files processed in the same invocation. By decompressing a specially crafted LZW file followed by a specially crafted LZH file in a single gzip -d command, an attacker can poison the shared global state and subsequently trigger an out‑of‑bounds read in the LZH decoder. The LZH decompression logic follows stale values left in the shared array, causing reads past the end of the allocated global buffer.  This issue has been fixed in commits 63dbf6b3b9e6e781df1a6a64e609b10e23969681 and e7378c2d421be6a286922374425680bbe9ad8b7d.

### CVE-2026-60000

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-60000](https://security-tracker.debian.org/tracker/CVE-2026-60000)

sshd in OpenSSH before 10.4 allows remote attackers to cause a denial of service (resource consumption from excessive authentication attempts) because MaxAuthTries was mishandled for GSSAPIAuthentication.

### CVE-2026-9538

- **Package:** `perl-base`
- **Installed:** `5.36.0-7+deb12u4`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-9538](https://security-tracker.debian.org/tracker/CVE-2026-9538)

Archive::Tar versions before 3.10 for Perl allow memory exhaustion via attacker controlled entry size field in tar header.  _read_tar() reads each entry's payload with $handle->read($$data, $block), where $block is derived from the entry's 12-byte size field in the tar header with no upper bound on that value.  A crafted header declaring a multi-gigabyte size causes Perl to allocate a scalar of that size.

### CVE-2026-85091

- **Package:** `zlib1g`
- **Installed:** `1:1.2.13.dfsg-1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-85091](https://security-tracker.debian.org/tracker/CVE-2026-85091)

zlib versions 1.3.1.2 through 1.3.2 contain a heap buffer overflow vulnerability in the gz_vacate() function when processing non-blocking gzwrite() operations with stale external buffer pointers. Attackers can trigger the overflow by calling gzprintf() or gzvprintf() after a write stall, causing an unchecked memmove() to write beyond the internal input buffer boundary.

### CVE-2025-69720

- **Package:** `libncursesw6`
- **Installed:** `6.4-4`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-69720](https://security-tracker.debian.org/tracker/CVE-2025-69720)

The infocmp command-line tool in ncurses before 6.5-20251213 has a stack-based buffer overflow in analyze_string in progs/infocmp.c.

### CVE-2025-69720

- **Package:** `libtinfo6`
- **Installed:** `6.4-4`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-69720](https://security-tracker.debian.org/tracker/CVE-2025-69720)

The infocmp command-line tool in ncurses before 6.5-20251213 has a stack-based buffer overflow in analyze_string in progs/infocmp.c.

### CVE-2025-69720

- **Package:** `ncurses-base`
- **Installed:** `6.4-4`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-69720](https://security-tracker.debian.org/tracker/CVE-2025-69720)

The infocmp command-line tool in ncurses before 6.5-20251213 has a stack-based buffer overflow in analyze_string in progs/infocmp.c.

### CVE-2025-69720

- **Package:** `ncurses-bin`
- **Installed:** `6.4-4`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-69720](https://security-tracker.debian.org/tracker/CVE-2025-69720)

The infocmp command-line tool in ncurses before 6.5-20251213 has a stack-based buffer overflow in analyze_string in progs/infocmp.c.

### CVE-2026-95619

- **Package:** `gcc-12-base`
- **Installed:** `12.2.0-14+deb12u1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-95619](https://security-tracker.debian.org/tracker/CVE-2026-95619)

A flaw was found in libstdc++. An integer overflow can occur when processing large inputs to the aligned operator new in the C++ library. This vulnerability could lead to an undersized memory allocation, potentially causing memory corruption or application instability.

### CVE-2026-95619

- **Package:** `libgcc-s1`
- **Installed:** `12.2.0-14+deb12u1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-95619](https://security-tracker.debian.org/tracker/CVE-2026-95619)

A flaw was found in libstdc++. An integer overflow can occur when processing large inputs to the aligned operator new in the C++ library. This vulnerability could lead to an undersized memory allocation, potentially causing memory corruption or application instability.

### CVE-2026-95619

- **Package:** `libstdc++6`
- **Installed:** `12.2.0-14+deb12u1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-95619](https://security-tracker.debian.org/tracker/CVE-2026-95619)

A flaw was found in libstdc++. An integer overflow can occur when processing large inputs to the aligned operator new in the C++ library. This vulnerability could lead to an undersized memory allocation, potentially causing memory corruption or application instability.

### CVE-2026-107778

- **Package:** `libgssapi-krb5-2`
- **Installed:** `1.20.1-2+deb12u5`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-107778](https://security-tracker.debian.org/tracker/CVE-2026-107778)

MIT Kerberos 5 (krb5) through 1.22.2 contains a NULL pointer dereference in make_cred_list() in rd_cred.c that allows authenticated Kerberos clients to crash services by sending mismatched KRB-CRED arrays. Attackers can send forwarded credentials with more tickets than ticket_info entries through gss_accept_sec_context() to crash GSS-API acceptor services, causing denial of service.

### CVE-2026-107778

- **Package:** `libk5crypto3`
- **Installed:** `1.20.1-2+deb12u5`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-107778](https://security-tracker.debian.org/tracker/CVE-2026-107778)

MIT Kerberos 5 (krb5) through 1.22.2 contains a NULL pointer dereference in make_cred_list() in rd_cred.c that allows authenticated Kerberos clients to crash services by sending mismatched KRB-CRED arrays. Attackers can send forwarded credentials with more tickets than ticket_info entries through gss_accept_sec_context() to crash GSS-API acceptor services, causing denial of service.

### CVE-2026-107778

- **Package:** `libkrb5-3`
- **Installed:** `1.20.1-2+deb12u5`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-107778](https://security-tracker.debian.org/tracker/CVE-2026-107778)

MIT Kerberos 5 (krb5) through 1.22.2 contains a NULL pointer dereference in make_cred_list() in rd_cred.c that allows authenticated Kerberos clients to crash services by sending mismatched KRB-CRED arrays. Attackers can send forwarded credentials with more tickets than ticket_info entries through gss_accept_sec_context() to crash GSS-API acceptor services, causing denial of service.

### CVE-2026-107778

- **Package:** `libkrb5support0`
- **Installed:** `1.20.1-2+deb12u5`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-107778](https://security-tracker.debian.org/tracker/CVE-2026-107778)

MIT Kerberos 5 (krb5) through 1.22.2 contains a NULL pointer dereference in make_cred_list() in rd_cred.c that allows authenticated Kerberos clients to crash services by sending mismatched KRB-CRED arrays. Attackers can send forwarded credentials with more tickets than ticket_info entries through gss_accept_sec_context() to crash GSS-API acceptor services, causing denial of service.

### CVE-2026-5928

- **Package:** `libc-bin`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-5928](https://security-tracker.debian.org/tracker/CVE-2026-5928)

Calling the ungetwc function on a FILE stream with wide characters encoded in a character set that has overlaps between its single byte and multi-byte character encodings, in the GNU C Library version 2.43 or earlier, may result in an attempt to read bytes before an allocated buffer, potentially resulting in unintentional disclosure of neighboring data in the heap, or a program crash.  A bug in the wide character pushback implementation (_IO_wdefault_pbackfail in libio/wgenops.c) causes ungetwc() to operate on the regular character buffer (fp->_IO_read_ptr) instead of the actual wide-stream read pointer (fp->_wide_data->_IO_read_ptr). The program crash may happen in cases where fp->_IO_read_ptr is not initialized and hence points to NULL. The buffer under-read requires a special situation where the input character encoding is such that there are overlaps between single byte representations and multibyte representations in that encoding, resulting in spurious matches. The spurious match case is not possible in the standard Unicode character sets.

### CVE-2026-5928

- **Package:** `libc6`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-5928](https://security-tracker.debian.org/tracker/CVE-2026-5928)

Calling the ungetwc function on a FILE stream with wide characters encoded in a character set that has overlaps between its single byte and multi-byte character encodings, in the GNU C Library version 2.43 or earlier, may result in an attempt to read bytes before an allocated buffer, potentially resulting in unintentional disclosure of neighboring data in the heap, or a program crash.  A bug in the wide character pushback implementation (_IO_wdefault_pbackfail in libio/wgenops.c) causes ungetwc() to operate on the regular character buffer (fp->_IO_read_ptr) instead of the actual wide-stream read pointer (fp->_wide_data->_IO_read_ptr). The program crash may happen in cases where fp->_IO_read_ptr is not initialized and hence points to NULL. The buffer under-read requires a special situation where the input character encoding is such that there are overlaps between single byte representations and multibyte representations in that encoding, resulting in spurious matches. The spurious match case is not possible in the standard Unicode character sets.

### CVE-2026-102010

- **Package:** `gcc-12-base`
- **Installed:** `12.2.0-14+deb12u1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-102010](https://security-tracker.debian.org/tracker/CVE-2026-102010)

A flaw was found in GCC. When an application calls the erase_if function on a binary heap priority queue in libstdc++, the library reallocates storage but fails to update its internal entry pointer. An attacker capable of triggering this operation can exploit this use-after-free condition, leading to a Denial of Service (DoS) via an application crash or potential memory corruption.

### CVE-2026-102010

- **Package:** `libgcc-s1`
- **Installed:** `12.2.0-14+deb12u1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-102010](https://security-tracker.debian.org/tracker/CVE-2026-102010)

A flaw was found in GCC. When an application calls the erase_if function on a binary heap priority queue in libstdc++, the library reallocates storage but fails to update its internal entry pointer. An attacker capable of triggering this operation can exploit this use-after-free condition, leading to a Denial of Service (DoS) via an application crash or potential memory corruption.

### CVE-2026-102010

- **Package:** `libstdc++6`
- **Installed:** `12.2.0-14+deb12u1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-102010](https://security-tracker.debian.org/tracker/CVE-2026-102010)

A flaw was found in GCC. When an application calls the erase_if function on a binary heap priority queue in libstdc++, the library reallocates storage but fails to update its internal entry pointer. An attacker capable of triggering this operation can exploit this use-after-free condition, leading to a Denial of Service (DoS) via an application crash or potential memory corruption.

### CVE-2026-19499

- **Package:** `libc-bin`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-19499](https://security-tracker.debian.org/tracker/CVE-2026-19499)

Calling strfmon and strfmon_l in the GNU C Library version 2.38 to 2.44 can write past the end of the caller-supplied output buffer when a conversion uses right-justified width padding.  Exploitation requires an application code path that calls strfmon or strfmon_l with right-justified width padding into a destination buffer that is large enough for the padding to succeed but too small for the internal memmove call. The field width or format may be attacker-influenced or a fixed susceptible pattern in the caller.  At the time of publication, no network-facing application impact is known.

### CVE-2026-19499

- **Package:** `libc6`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-19499](https://security-tracker.debian.org/tracker/CVE-2026-19499)

Calling strfmon and strfmon_l in the GNU C Library version 2.38 to 2.44 can write past the end of the caller-supplied output buffer when a conversion uses right-justified width padding.  Exploitation requires an application code path that calls strfmon or strfmon_l with right-justified width padding into a destination buffer that is large enough for the padding to succeed but too small for the internal memmove call. The field width or format may be attacker-influenced or a fixed susceptible pattern in the caller.  At the time of publication, no network-facing application impact is known.

### CVE-2026-5435

- **Package:** `libc-bin`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-5435](https://security-tracker.debian.org/tracker/CVE-2026-5435)

The deprecated functions ns_printrrf, ns_printrr and fp_nquery in the GNU C Library version 2.2 and newer fail to enforce the caller-supplied buffer length, and can result in an out-of-bounds write when printing TSIG records.

### CVE-2026-5435

- **Package:** `libc6`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-5435](https://security-tracker.debian.org/tracker/CVE-2026-5435)

The deprecated functions ns_printrrf, ns_printrr and fp_nquery in the GNU C Library version 2.2 and newer fail to enforce the caller-supplied buffer length, and can result in an out-of-bounds write when printing TSIG records.

### CVE-2026-76642

- **Package:** `bsdutils`
- **Installed:** `1:2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-76642](https://security-tracker.debian.org/tracker/CVE-2026-76642)

util-linux versions through 2.41.5 and 2.42.2 fail to check mount helper exit status before running post-mount hooks, allowing unprivileged users to execute privileged operations on pre-existing filesystems. Attackers can exploit X-mount.idmap or X-mount.owner hooks to clone filesystems with inherited suid bits or modify target inode permissions after a helper fails, achieving privilege escalation.

### CVE-2026-76642

- **Package:** `libblkid1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-76642](https://security-tracker.debian.org/tracker/CVE-2026-76642)

util-linux versions through 2.41.5 and 2.42.2 fail to check mount helper exit status before running post-mount hooks, allowing unprivileged users to execute privileged operations on pre-existing filesystems. Attackers can exploit X-mount.idmap or X-mount.owner hooks to clone filesystems with inherited suid bits or modify target inode permissions after a helper fails, achieving privilege escalation.

### CVE-2026-76642

- **Package:** `libmount1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-76642](https://security-tracker.debian.org/tracker/CVE-2026-76642)

util-linux versions through 2.41.5 and 2.42.2 fail to check mount helper exit status before running post-mount hooks, allowing unprivileged users to execute privileged operations on pre-existing filesystems. Attackers can exploit X-mount.idmap or X-mount.owner hooks to clone filesystems with inherited suid bits or modify target inode permissions after a helper fails, achieving privilege escalation.

### CVE-2026-76642

- **Package:** `libsmartcols1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-76642](https://security-tracker.debian.org/tracker/CVE-2026-76642)

util-linux versions through 2.41.5 and 2.42.2 fail to check mount helper exit status before running post-mount hooks, allowing unprivileged users to execute privileged operations on pre-existing filesystems. Attackers can exploit X-mount.idmap or X-mount.owner hooks to clone filesystems with inherited suid bits or modify target inode permissions after a helper fails, achieving privilege escalation.

### CVE-2026-76642

- **Package:** `libuuid1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-76642](https://security-tracker.debian.org/tracker/CVE-2026-76642)

util-linux versions through 2.41.5 and 2.42.2 fail to check mount helper exit status before running post-mount hooks, allowing unprivileged users to execute privileged operations on pre-existing filesystems. Attackers can exploit X-mount.idmap or X-mount.owner hooks to clone filesystems with inherited suid bits or modify target inode permissions after a helper fails, achieving privilege escalation.

### CVE-2026-76642

- **Package:** `mount`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-76642](https://security-tracker.debian.org/tracker/CVE-2026-76642)

util-linux versions through 2.41.5 and 2.42.2 fail to check mount helper exit status before running post-mount hooks, allowing unprivileged users to execute privileged operations on pre-existing filesystems. Attackers can exploit X-mount.idmap or X-mount.owner hooks to clone filesystems with inherited suid bits or modify target inode permissions after a helper fails, achieving privilege escalation.

### CVE-2026-76642

- **Package:** `util-linux`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-76642](https://security-tracker.debian.org/tracker/CVE-2026-76642)

util-linux versions through 2.41.5 and 2.42.2 fail to check mount helper exit status before running post-mount hooks, allowing unprivileged users to execute privileged operations on pre-existing filesystems. Attackers can exploit X-mount.idmap or X-mount.owner hooks to clone filesystems with inherited suid bits or modify target inode permissions after a helper fails, achieving privilege escalation.

### CVE-2026-76642

- **Package:** `util-linux-extra`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-76642](https://security-tracker.debian.org/tracker/CVE-2026-76642)

util-linux versions through 2.41.5 and 2.42.2 fail to check mount helper exit status before running post-mount hooks, allowing unprivileged users to execute privileged operations on pre-existing filesystems. Attackers can exploit X-mount.idmap or X-mount.owner hooks to clone filesystems with inherited suid bits or modify target inode permissions after a helper fails, achieving privilege escalation.

### CVE-2026-78408

- **Package:** `bsdutils`
- **Installed:** `1:2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-78408](https://security-tracker.debian.org/tracker/CVE-2026-78408)

The nsenter --join-cgroup option opens the target cgroup.procs file as root and leaves that file descriptor open across later namespace and credential changes and across execve(). Because the kernel checks later cgroup migrations using the credentials from the original open, a program run in an attacker-controlled target can inherit root's ability to move host processes between cgroups. After a privileged operator uses --join-cgroup against that target, an unprivileged user can migrate and terminate unrelated root processes.

### CVE-2026-78408

- **Package:** `libblkid1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-78408](https://security-tracker.debian.org/tracker/CVE-2026-78408)

The nsenter --join-cgroup option opens the target cgroup.procs file as root and leaves that file descriptor open across later namespace and credential changes and across execve(). Because the kernel checks later cgroup migrations using the credentials from the original open, a program run in an attacker-controlled target can inherit root's ability to move host processes between cgroups. After a privileged operator uses --join-cgroup against that target, an unprivileged user can migrate and terminate unrelated root processes.

### CVE-2026-78408

- **Package:** `libmount1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-78408](https://security-tracker.debian.org/tracker/CVE-2026-78408)

The nsenter --join-cgroup option opens the target cgroup.procs file as root and leaves that file descriptor open across later namespace and credential changes and across execve(). Because the kernel checks later cgroup migrations using the credentials from the original open, a program run in an attacker-controlled target can inherit root's ability to move host processes between cgroups. After a privileged operator uses --join-cgroup against that target, an unprivileged user can migrate and terminate unrelated root processes.

### CVE-2026-78408

- **Package:** `libsmartcols1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-78408](https://security-tracker.debian.org/tracker/CVE-2026-78408)

The nsenter --join-cgroup option opens the target cgroup.procs file as root and leaves that file descriptor open across later namespace and credential changes and across execve(). Because the kernel checks later cgroup migrations using the credentials from the original open, a program run in an attacker-controlled target can inherit root's ability to move host processes between cgroups. After a privileged operator uses --join-cgroup against that target, an unprivileged user can migrate and terminate unrelated root processes.

### CVE-2026-78408

- **Package:** `libuuid1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-78408](https://security-tracker.debian.org/tracker/CVE-2026-78408)

The nsenter --join-cgroup option opens the target cgroup.procs file as root and leaves that file descriptor open across later namespace and credential changes and across execve(). Because the kernel checks later cgroup migrations using the credentials from the original open, a program run in an attacker-controlled target can inherit root's ability to move host processes between cgroups. After a privileged operator uses --join-cgroup against that target, an unprivileged user can migrate and terminate unrelated root processes.

### CVE-2026-78408

- **Package:** `mount`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-78408](https://security-tracker.debian.org/tracker/CVE-2026-78408)

The nsenter --join-cgroup option opens the target cgroup.procs file as root and leaves that file descriptor open across later namespace and credential changes and across execve(). Because the kernel checks later cgroup migrations using the credentials from the original open, a program run in an attacker-controlled target can inherit root's ability to move host processes between cgroups. After a privileged operator uses --join-cgroup against that target, an unprivileged user can migrate and terminate unrelated root processes.

### CVE-2026-78408

- **Package:** `util-linux`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-78408](https://security-tracker.debian.org/tracker/CVE-2026-78408)

The nsenter --join-cgroup option opens the target cgroup.procs file as root and leaves that file descriptor open across later namespace and credential changes and across execve(). Because the kernel checks later cgroup migrations using the credentials from the original open, a program run in an attacker-controlled target can inherit root's ability to move host processes between cgroups. After a privileged operator uses --join-cgroup against that target, an unprivileged user can migrate and terminate unrelated root processes.

### CVE-2026-78408

- **Package:** `util-linux-extra`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-78408](https://security-tracker.debian.org/tracker/CVE-2026-78408)

The nsenter --join-cgroup option opens the target cgroup.procs file as root and leaves that file descriptor open across later namespace and credential changes and across execve(). Because the kernel checks later cgroup migrations using the credentials from the original open, a program run in an attacker-controlled target can inherit root's ability to move host processes between cgroups. After a privileged operator uses --join-cgroup against that target, an unprivileged user can migrate and terminate unrelated root processes.

### CVE-2026-11824

- **Package:** `libsqlite3-0`
- **Installed:** `3.40.1-2+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-11824](https://security-tracker.debian.org/tracker/CVE-2026-11824)

SQLite before 3.53.2 contains a heap-based buffer overflow vulnerability in the FTS5 full-text search extension that allows attackers to cause a crash or execute arbitrary code by supplying a crafted database with malicious continuation page metadata specifying a szLeaf value smaller than 4. Attackers can trigger an integer underflow in fts5ChunkIterate() causing an inflated remaining byte count during FTS5 MATCH query processing, leading to a heap buffer overflow of attacker-controlled data in applications compiled with SQLITE_ENABLE_FTS5.

### CVE-2026-11824

- **Package:** `sqlite3`
- **Installed:** `3.40.1-2+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-11824](https://security-tracker.debian.org/tracker/CVE-2026-11824)

SQLite before 3.53.2 contains a heap-based buffer overflow vulnerability in the FTS5 full-text search extension that allows attackers to cause a crash or execute arbitrary code by supplying a crafted database with malicious continuation page metadata specifying a szLeaf value smaller than 4. Attackers can trigger an integer underflow in fts5ChunkIterate() causing an inflated remaining byte count during FTS5 MATCH query processing, leading to a heap buffer overflow of attacker-controlled data in applications compiled with SQLITE_ENABLE_FTS5.

### CVE-2026-53615

- **Package:** `bsdutils`
- **Installed:** `1:2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-53615](https://security-tracker.debian.org/tracker/CVE-2026-53615)

util-linux is a random collection of Linux utilities. Before util-linux 2.41.4, `parse_dos_extended()` in `libblkid/src/partitions/dos.c` computes an extended-partition start sector with 32-bit addition and does not apply the extended-area bounds checks to the first two EBR entries. A local attacker who causes a crafted DOS extended-partition disk image or removable medium to be probed can wrap `cur_start + start` to sector zero and cause libblkid to report a false partition overlapping the MBR. This directly compromises the integrity of the reported partition metadata; disk modification or availability loss requires a separate downstream consumer to act on that metadata. This issue is fixed in 2.41.4.

### CVE-2026-53615

- **Package:** `libblkid1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-53615](https://security-tracker.debian.org/tracker/CVE-2026-53615)

util-linux is a random collection of Linux utilities. Before util-linux 2.41.4, `parse_dos_extended()` in `libblkid/src/partitions/dos.c` computes an extended-partition start sector with 32-bit addition and does not apply the extended-area bounds checks to the first two EBR entries. A local attacker who causes a crafted DOS extended-partition disk image or removable medium to be probed can wrap `cur_start + start` to sector zero and cause libblkid to report a false partition overlapping the MBR. This directly compromises the integrity of the reported partition metadata; disk modification or availability loss requires a separate downstream consumer to act on that metadata. This issue is fixed in 2.41.4.

### CVE-2026-53615

- **Package:** `libmount1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-53615](https://security-tracker.debian.org/tracker/CVE-2026-53615)

util-linux is a random collection of Linux utilities. Before util-linux 2.41.4, `parse_dos_extended()` in `libblkid/src/partitions/dos.c` computes an extended-partition start sector with 32-bit addition and does not apply the extended-area bounds checks to the first two EBR entries. A local attacker who causes a crafted DOS extended-partition disk image or removable medium to be probed can wrap `cur_start + start` to sector zero and cause libblkid to report a false partition overlapping the MBR. This directly compromises the integrity of the reported partition metadata; disk modification or availability loss requires a separate downstream consumer to act on that metadata. This issue is fixed in 2.41.4.

### CVE-2026-53615

- **Package:** `libsmartcols1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-53615](https://security-tracker.debian.org/tracker/CVE-2026-53615)

util-linux is a random collection of Linux utilities. Before util-linux 2.41.4, `parse_dos_extended()` in `libblkid/src/partitions/dos.c` computes an extended-partition start sector with 32-bit addition and does not apply the extended-area bounds checks to the first two EBR entries. A local attacker who causes a crafted DOS extended-partition disk image or removable medium to be probed can wrap `cur_start + start` to sector zero and cause libblkid to report a false partition overlapping the MBR. This directly compromises the integrity of the reported partition metadata; disk modification or availability loss requires a separate downstream consumer to act on that metadata. This issue is fixed in 2.41.4.

### CVE-2026-53615

- **Package:** `libuuid1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-53615](https://security-tracker.debian.org/tracker/CVE-2026-53615)

util-linux is a random collection of Linux utilities. Before util-linux 2.41.4, `parse_dos_extended()` in `libblkid/src/partitions/dos.c` computes an extended-partition start sector with 32-bit addition and does not apply the extended-area bounds checks to the first two EBR entries. A local attacker who causes a crafted DOS extended-partition disk image or removable medium to be probed can wrap `cur_start + start` to sector zero and cause libblkid to report a false partition overlapping the MBR. This directly compromises the integrity of the reported partition metadata; disk modification or availability loss requires a separate downstream consumer to act on that metadata. This issue is fixed in 2.41.4.

### CVE-2026-53615

- **Package:** `mount`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-53615](https://security-tracker.debian.org/tracker/CVE-2026-53615)

util-linux is a random collection of Linux utilities. Before util-linux 2.41.4, `parse_dos_extended()` in `libblkid/src/partitions/dos.c` computes an extended-partition start sector with 32-bit addition and does not apply the extended-area bounds checks to the first two EBR entries. A local attacker who causes a crafted DOS extended-partition disk image or removable medium to be probed can wrap `cur_start + start` to sector zero and cause libblkid to report a false partition overlapping the MBR. This directly compromises the integrity of the reported partition metadata; disk modification or availability loss requires a separate downstream consumer to act on that metadata. This issue is fixed in 2.41.4.

### CVE-2026-53615

- **Package:** `util-linux`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-53615](https://security-tracker.debian.org/tracker/CVE-2026-53615)

util-linux is a random collection of Linux utilities. Before util-linux 2.41.4, `parse_dos_extended()` in `libblkid/src/partitions/dos.c` computes an extended-partition start sector with 32-bit addition and does not apply the extended-area bounds checks to the first two EBR entries. A local attacker who causes a crafted DOS extended-partition disk image or removable medium to be probed can wrap `cur_start + start` to sector zero and cause libblkid to report a false partition overlapping the MBR. This directly compromises the integrity of the reported partition metadata; disk modification or availability loss requires a separate downstream consumer to act on that metadata. This issue is fixed in 2.41.4.

### CVE-2026-53615

- **Package:** `util-linux-extra`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-53615](https://security-tracker.debian.org/tracker/CVE-2026-53615)

util-linux is a random collection of Linux utilities. Before util-linux 2.41.4, `parse_dos_extended()` in `libblkid/src/partitions/dos.c` computes an extended-partition start sector with 32-bit addition and does not apply the extended-area bounds checks to the first two EBR entries. A local attacker who causes a crafted DOS extended-partition disk image or removable medium to be probed can wrap `cur_start + start` to sector zero and cause libblkid to report a false partition overlapping the MBR. This directly compromises the integrity of the reported partition metadata; disk modification or availability loss requires a separate downstream consumer to act on that metadata. This issue is fixed in 2.41.4.

### CVE-2026-78409

- **Package:** `bsdutils`
- **Installed:** `1:2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-78409](https://security-tracker.debian.org/tracker/CVE-2026-78409)

The X-mount.subdir option uses a detached-tree fast path on Linux 6.15 and later and passes the configured subdirectory to open_tree() with AT_SYMLINK_NOFOLLOW. That flag does not stop intermediate symlink traversal or keep resolution inside the newly mounted filesystem. A local unprivileged user with an fstab-authorized X-mount.subdir entry can attach a host path at the intended mountpoint.

### CVE-2026-78409

- **Package:** `libblkid1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-78409](https://security-tracker.debian.org/tracker/CVE-2026-78409)

The X-mount.subdir option uses a detached-tree fast path on Linux 6.15 and later and passes the configured subdirectory to open_tree() with AT_SYMLINK_NOFOLLOW. That flag does not stop intermediate symlink traversal or keep resolution inside the newly mounted filesystem. A local unprivileged user with an fstab-authorized X-mount.subdir entry can attach a host path at the intended mountpoint.

### CVE-2026-78409

- **Package:** `libmount1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-78409](https://security-tracker.debian.org/tracker/CVE-2026-78409)

The X-mount.subdir option uses a detached-tree fast path on Linux 6.15 and later and passes the configured subdirectory to open_tree() with AT_SYMLINK_NOFOLLOW. That flag does not stop intermediate symlink traversal or keep resolution inside the newly mounted filesystem. A local unprivileged user with an fstab-authorized X-mount.subdir entry can attach a host path at the intended mountpoint.

### CVE-2026-78409

- **Package:** `libsmartcols1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-78409](https://security-tracker.debian.org/tracker/CVE-2026-78409)

The X-mount.subdir option uses a detached-tree fast path on Linux 6.15 and later and passes the configured subdirectory to open_tree() with AT_SYMLINK_NOFOLLOW. That flag does not stop intermediate symlink traversal or keep resolution inside the newly mounted filesystem. A local unprivileged user with an fstab-authorized X-mount.subdir entry can attach a host path at the intended mountpoint.

### CVE-2026-78409

- **Package:** `libuuid1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-78409](https://security-tracker.debian.org/tracker/CVE-2026-78409)

The X-mount.subdir option uses a detached-tree fast path on Linux 6.15 and later and passes the configured subdirectory to open_tree() with AT_SYMLINK_NOFOLLOW. That flag does not stop intermediate symlink traversal or keep resolution inside the newly mounted filesystem. A local unprivileged user with an fstab-authorized X-mount.subdir entry can attach a host path at the intended mountpoint.

### CVE-2026-78409

- **Package:** `mount`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-78409](https://security-tracker.debian.org/tracker/CVE-2026-78409)

The X-mount.subdir option uses a detached-tree fast path on Linux 6.15 and later and passes the configured subdirectory to open_tree() with AT_SYMLINK_NOFOLLOW. That flag does not stop intermediate symlink traversal or keep resolution inside the newly mounted filesystem. A local unprivileged user with an fstab-authorized X-mount.subdir entry can attach a host path at the intended mountpoint.

### CVE-2026-78409

- **Package:** `util-linux`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-78409](https://security-tracker.debian.org/tracker/CVE-2026-78409)

The X-mount.subdir option uses a detached-tree fast path on Linux 6.15 and later and passes the configured subdirectory to open_tree() with AT_SYMLINK_NOFOLLOW. That flag does not stop intermediate symlink traversal or keep resolution inside the newly mounted filesystem. A local unprivileged user with an fstab-authorized X-mount.subdir entry can attach a host path at the intended mountpoint.

### CVE-2026-78409

- **Package:** `util-linux-extra`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-78409](https://security-tracker.debian.org/tracker/CVE-2026-78409)

The X-mount.subdir option uses a detached-tree fast path on Linux 6.15 and later and passes the configured subdirectory to open_tree() with AT_SYMLINK_NOFOLLOW. That flag does not stop intermediate symlink traversal or keep resolution inside the newly mounted filesystem. A local unprivileged user with an fstab-authorized X-mount.subdir entry can attach a host path at the intended mountpoint.

### CVE-2026-78410

- **Package:** `bsdutils`
- **Installed:** `1:2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-78410](https://security-tracker.debian.org/tracker/CVE-2026-78410)

A flaw was found in util-linux. Restricted bind mounts take the source path from fstab but do not pin that source before the privileged mount. A local unprivileged user who can replace the authorized source or a writable ancestor can redirect SUID mount(8) to bind another host directory. If the fstab entry also sets X-mount.owner, X-mount.group, or X-mount.mode, root then changes ownership or mode on that redirected inode.

### CVE-2026-78410

- **Package:** `libblkid1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-78410](https://security-tracker.debian.org/tracker/CVE-2026-78410)

A flaw was found in util-linux. Restricted bind mounts take the source path from fstab but do not pin that source before the privileged mount. A local unprivileged user who can replace the authorized source or a writable ancestor can redirect SUID mount(8) to bind another host directory. If the fstab entry also sets X-mount.owner, X-mount.group, or X-mount.mode, root then changes ownership or mode on that redirected inode.

### CVE-2026-78410

- **Package:** `libmount1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-78410](https://security-tracker.debian.org/tracker/CVE-2026-78410)

A flaw was found in util-linux. Restricted bind mounts take the source path from fstab but do not pin that source before the privileged mount. A local unprivileged user who can replace the authorized source or a writable ancestor can redirect SUID mount(8) to bind another host directory. If the fstab entry also sets X-mount.owner, X-mount.group, or X-mount.mode, root then changes ownership or mode on that redirected inode.

### CVE-2026-78410

- **Package:** `libsmartcols1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-78410](https://security-tracker.debian.org/tracker/CVE-2026-78410)

A flaw was found in util-linux. Restricted bind mounts take the source path from fstab but do not pin that source before the privileged mount. A local unprivileged user who can replace the authorized source or a writable ancestor can redirect SUID mount(8) to bind another host directory. If the fstab entry also sets X-mount.owner, X-mount.group, or X-mount.mode, root then changes ownership or mode on that redirected inode.

### CVE-2026-78410

- **Package:** `libuuid1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-78410](https://security-tracker.debian.org/tracker/CVE-2026-78410)

A flaw was found in util-linux. Restricted bind mounts take the source path from fstab but do not pin that source before the privileged mount. A local unprivileged user who can replace the authorized source or a writable ancestor can redirect SUID mount(8) to bind another host directory. If the fstab entry also sets X-mount.owner, X-mount.group, or X-mount.mode, root then changes ownership or mode on that redirected inode.

### CVE-2026-78410

- **Package:** `mount`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-78410](https://security-tracker.debian.org/tracker/CVE-2026-78410)

A flaw was found in util-linux. Restricted bind mounts take the source path from fstab but do not pin that source before the privileged mount. A local unprivileged user who can replace the authorized source or a writable ancestor can redirect SUID mount(8) to bind another host directory. If the fstab entry also sets X-mount.owner, X-mount.group, or X-mount.mode, root then changes ownership or mode on that redirected inode.

### CVE-2026-78410

- **Package:** `util-linux`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-78410](https://security-tracker.debian.org/tracker/CVE-2026-78410)

A flaw was found in util-linux. Restricted bind mounts take the source path from fstab but do not pin that source before the privileged mount. A local unprivileged user who can replace the authorized source or a writable ancestor can redirect SUID mount(8) to bind another host directory. If the fstab entry also sets X-mount.owner, X-mount.group, or X-mount.mode, root then changes ownership or mode on that redirected inode.

### CVE-2026-78410

- **Package:** `util-linux-extra`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-78410](https://security-tracker.debian.org/tracker/CVE-2026-78410)

A flaw was found in util-linux. Restricted bind mounts take the source path from fstab but do not pin that source before the privileged mount. A local unprivileged user who can replace the authorized source or a writable ancestor can redirect SUID mount(8) to bind another host directory. If the fstab entry also sets X-mount.owner, X-mount.group, or X-mount.mode, root then changes ownership or mode on that redirected inode.

### CVE-2026-59999

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-59999](https://security-tracker.debian.org/tracker/CVE-2026-59999)

In sshd in OpenSSH before 10.4, DisableForwarding=yes was supposed to take precedence over PermitTunnel=yes, but did not.

### CVE-2026-53613

- **Package:** `bsdutils`
- **Installed:** `1:2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-53613](https://security-tracker.debian.org/tracker/CVE-2026-53613)

util-linux is a random collection of Linux utilities. In util-linux 2.17 through 2.41.6 and 2.42 through 2.42.3, and in 2.42.4 when the legacy `mount(2)` path is used without `/proc`, restricted non-root `mount` requests validate an `/etc/fstab` target before the mount operation re-resolves that pathname. A local low-privileged user authorized by an fstab `user` or `users` entry whose target has an attacker-writable ancestor can use `renameat2(RENAME_EXCHANGE)` to swap a path component and redirect an authorized mount to a root-owned location, such as mounting attacker-controlled content over `/etc/sudoers.d`, and thereby gain root privileges. Versions 2.41.5 and 2.42.2 pin targets for the new mount API, and 2.42.4 pins legacy targets through `/proc/self/fd`; the documented legacy fallback without `/proc` remains affected.

### CVE-2026-53613

- **Package:** `libblkid1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-53613](https://security-tracker.debian.org/tracker/CVE-2026-53613)

util-linux is a random collection of Linux utilities. In util-linux 2.17 through 2.41.6 and 2.42 through 2.42.3, and in 2.42.4 when the legacy `mount(2)` path is used without `/proc`, restricted non-root `mount` requests validate an `/etc/fstab` target before the mount operation re-resolves that pathname. A local low-privileged user authorized by an fstab `user` or `users` entry whose target has an attacker-writable ancestor can use `renameat2(RENAME_EXCHANGE)` to swap a path component and redirect an authorized mount to a root-owned location, such as mounting attacker-controlled content over `/etc/sudoers.d`, and thereby gain root privileges. Versions 2.41.5 and 2.42.2 pin targets for the new mount API, and 2.42.4 pins legacy targets through `/proc/self/fd`; the documented legacy fallback without `/proc` remains affected.

### CVE-2026-53613

- **Package:** `libmount1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-53613](https://security-tracker.debian.org/tracker/CVE-2026-53613)

util-linux is a random collection of Linux utilities. In util-linux 2.17 through 2.41.6 and 2.42 through 2.42.3, and in 2.42.4 when the legacy `mount(2)` path is used without `/proc`, restricted non-root `mount` requests validate an `/etc/fstab` target before the mount operation re-resolves that pathname. A local low-privileged user authorized by an fstab `user` or `users` entry whose target has an attacker-writable ancestor can use `renameat2(RENAME_EXCHANGE)` to swap a path component and redirect an authorized mount to a root-owned location, such as mounting attacker-controlled content over `/etc/sudoers.d`, and thereby gain root privileges. Versions 2.41.5 and 2.42.2 pin targets for the new mount API, and 2.42.4 pins legacy targets through `/proc/self/fd`; the documented legacy fallback without `/proc` remains affected.

### CVE-2026-53613

- **Package:** `libsmartcols1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-53613](https://security-tracker.debian.org/tracker/CVE-2026-53613)

util-linux is a random collection of Linux utilities. In util-linux 2.17 through 2.41.6 and 2.42 through 2.42.3, and in 2.42.4 when the legacy `mount(2)` path is used without `/proc`, restricted non-root `mount` requests validate an `/etc/fstab` target before the mount operation re-resolves that pathname. A local low-privileged user authorized by an fstab `user` or `users` entry whose target has an attacker-writable ancestor can use `renameat2(RENAME_EXCHANGE)` to swap a path component and redirect an authorized mount to a root-owned location, such as mounting attacker-controlled content over `/etc/sudoers.d`, and thereby gain root privileges. Versions 2.41.5 and 2.42.2 pin targets for the new mount API, and 2.42.4 pins legacy targets through `/proc/self/fd`; the documented legacy fallback without `/proc` remains affected.

### CVE-2026-53613

- **Package:** `libuuid1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-53613](https://security-tracker.debian.org/tracker/CVE-2026-53613)

util-linux is a random collection of Linux utilities. In util-linux 2.17 through 2.41.6 and 2.42 through 2.42.3, and in 2.42.4 when the legacy `mount(2)` path is used without `/proc`, restricted non-root `mount` requests validate an `/etc/fstab` target before the mount operation re-resolves that pathname. A local low-privileged user authorized by an fstab `user` or `users` entry whose target has an attacker-writable ancestor can use `renameat2(RENAME_EXCHANGE)` to swap a path component and redirect an authorized mount to a root-owned location, such as mounting attacker-controlled content over `/etc/sudoers.d`, and thereby gain root privileges. Versions 2.41.5 and 2.42.2 pin targets for the new mount API, and 2.42.4 pins legacy targets through `/proc/self/fd`; the documented legacy fallback without `/proc` remains affected.

### CVE-2026-53613

- **Package:** `mount`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-53613](https://security-tracker.debian.org/tracker/CVE-2026-53613)

util-linux is a random collection of Linux utilities. In util-linux 2.17 through 2.41.6 and 2.42 through 2.42.3, and in 2.42.4 when the legacy `mount(2)` path is used without `/proc`, restricted non-root `mount` requests validate an `/etc/fstab` target before the mount operation re-resolves that pathname. A local low-privileged user authorized by an fstab `user` or `users` entry whose target has an attacker-writable ancestor can use `renameat2(RENAME_EXCHANGE)` to swap a path component and redirect an authorized mount to a root-owned location, such as mounting attacker-controlled content over `/etc/sudoers.d`, and thereby gain root privileges. Versions 2.41.5 and 2.42.2 pin targets for the new mount API, and 2.42.4 pins legacy targets through `/proc/self/fd`; the documented legacy fallback without `/proc` remains affected.

### CVE-2026-53613

- **Package:** `util-linux`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-53613](https://security-tracker.debian.org/tracker/CVE-2026-53613)

util-linux is a random collection of Linux utilities. In util-linux 2.17 through 2.41.6 and 2.42 through 2.42.3, and in 2.42.4 when the legacy `mount(2)` path is used without `/proc`, restricted non-root `mount` requests validate an `/etc/fstab` target before the mount operation re-resolves that pathname. A local low-privileged user authorized by an fstab `user` or `users` entry whose target has an attacker-writable ancestor can use `renameat2(RENAME_EXCHANGE)` to swap a path component and redirect an authorized mount to a root-owned location, such as mounting attacker-controlled content over `/etc/sudoers.d`, and thereby gain root privileges. Versions 2.41.5 and 2.42.2 pin targets for the new mount API, and 2.42.4 pins legacy targets through `/proc/self/fd`; the documented legacy fallback without `/proc` remains affected.

### CVE-2026-53613

- **Package:** `util-linux-extra`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-53613](https://security-tracker.debian.org/tracker/CVE-2026-53613)

util-linux is a random collection of Linux utilities. In util-linux 2.17 through 2.41.6 and 2.42 through 2.42.3, and in 2.42.4 when the legacy `mount(2)` path is used without `/proc`, restricted non-root `mount` requests validate an `/etc/fstab` target before the mount operation re-resolves that pathname. A local low-privileged user authorized by an fstab `user` or `users` entry whose target has an attacker-writable ancestor can use `renameat2(RENAME_EXCHANGE)` to swap a path component and redirect an authorized mount to a root-owned location, such as mounting attacker-controlled content over `/etc/sudoers.d`, and thereby gain root privileges. Versions 2.41.5 and 2.42.2 pin targets for the new mount API, and 2.42.4 pins legacy targets through `/proc/self/fd`; the documented legacy fallback without `/proc` remains affected.

### CVE-2026-106583

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-106583](https://security-tracker.debian.org/tracker/CVE-2026-106583)

In ssh in OpenSSH before 10.6, a $ or \ character can occur in a command-line username, leading to injection.

### CVE-2026-54369

- **Package:** `libacl1`
- **Installed:** `2.3.1-3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-54369](https://security-tracker.debian.org/tracker/CVE-2026-54369)

acl before version 2.4.0 contains a symlink traversal vulnerability in the libacl pathname-based functions acl_get_file(), acl_set_file(), acl_extended_file(), and acl_delete_def_file() that allows local attackers to escalate privileges by replacing any pathname component with a symbolic link. Attackers who control any component of a pathname processed by a privileged caller can redirect ACL read or write operations to arbitrary files or directories, enabling unauthorized manipulation of access control lists and local privilege escalation.

### CVE-2026-106553

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-106553](https://security-tracker.debian.org/tracker/CVE-2026-106553)

In sshd in OpenSSH before 10.6, credentials can incorrectly persist after failure of a GSSAPIAuthentication authentication attempt.

### CVE-2026-106555

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-106555](https://security-tracker.debian.org/tracker/CVE-2026-106555)

In sshd in OpenSSH before 10.6, GSSAPIAuthentication authentication state can incorrectly be persisted across authentication attempts.

### CVE-2026-54370

- **Package:** `libacl1`
- **Installed:** `2.3.1-3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-54370](https://security-tracker.debian.org/tracker/CVE-2026-54370)

acl before version 2.4.0 contains a time-of-check to time-of-use (TOCTOU) race condition vulnerability that allows local attackers to escalate privileges by replacing a pathname component with a symbolic link between an lstat() check and subsequent symlink-following operations such as stat(), chown(), chmod(), acl_get_file(), and acl_set_file(). Attackers who control a pathname component can redirect file access control list operations to arbitrary files when getfacl, setfacl, or chacl is invoked by a privileged process over an attacker-controlled path, resulting in local privilege escalation.

### CVE-2026-84243

- **Package:** `libc-bin`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-84243](https://security-tracker.debian.org/tracker/CVE-2026-84243)

### CVE-2026-84243

- **Package:** `libc6`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-84243](https://security-tracker.debian.org/tracker/CVE-2026-84243)

## Medium (96)

### CVE-2023-50495

- **Package:** `libncursesw6`
- **Installed:** `6.4-4`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2023-50495](https://security-tracker.debian.org/tracker/CVE-2023-50495)

NCurse v6.4-20230418 was discovered to contain a segmentation fault via the component _nc_wrap_entry().

### CVE-2023-50495

- **Package:** `libtinfo6`
- **Installed:** `6.4-4`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2023-50495](https://security-tracker.debian.org/tracker/CVE-2023-50495)

NCurse v6.4-20230418 was discovered to contain a segmentation fault via the component _nc_wrap_entry().

### CVE-2023-50495

- **Package:** `ncurses-base`
- **Installed:** `6.4-4`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2023-50495](https://security-tracker.debian.org/tracker/CVE-2023-50495)

NCurse v6.4-20230418 was discovered to contain a segmentation fault via the component _nc_wrap_entry().

### CVE-2023-50495

- **Package:** `ncurses-bin`
- **Installed:** `6.4-4`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2023-50495](https://security-tracker.debian.org/tracker/CVE-2023-50495)

NCurse v6.4-20230418 was discovered to contain a segmentation fault via the component _nc_wrap_entry().

### CVE-2026-107708

- **Package:** `libgssapi-krb5-2`
- **Installed:** `1.20.1-2+deb12u5`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-107708](https://security-tracker.debian.org/tracker/CVE-2026-107708)

MIT krb5 through 1.22.2 contains a NULL pointer dereference vulnerability in the KDC's get_pac_princ_with_realm() that returns success while leaving the client principal NULL on malformed names. A malicious or compromised cross-realm trusted KDC can send an S4U2Proxy request with a PAC carrying a malformed client name to crash krb5kdc and deny authentication.

### CVE-2026-107708

- **Package:** `libk5crypto3`
- **Installed:** `1.20.1-2+deb12u5`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-107708](https://security-tracker.debian.org/tracker/CVE-2026-107708)

MIT krb5 through 1.22.2 contains a NULL pointer dereference vulnerability in the KDC's get_pac_princ_with_realm() that returns success while leaving the client principal NULL on malformed names. A malicious or compromised cross-realm trusted KDC can send an S4U2Proxy request with a PAC carrying a malformed client name to crash krb5kdc and deny authentication.

### CVE-2026-107708

- **Package:** `libkrb5-3`
- **Installed:** `1.20.1-2+deb12u5`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-107708](https://security-tracker.debian.org/tracker/CVE-2026-107708)

MIT krb5 through 1.22.2 contains a NULL pointer dereference vulnerability in the KDC's get_pac_princ_with_realm() that returns success while leaving the client principal NULL on malformed names. A malicious or compromised cross-realm trusted KDC can send an S4U2Proxy request with a PAC carrying a malformed client name to crash krb5kdc and deny authentication.

### CVE-2026-107708

- **Package:** `libkrb5support0`
- **Installed:** `1.20.1-2+deb12u5`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-107708](https://security-tracker.debian.org/tracker/CVE-2026-107708)

MIT krb5 through 1.22.2 contains a NULL pointer dereference vulnerability in the KDC's get_pac_princ_with_realm() that returns success while leaving the client principal NULL on malformed names. A malicious or compromised cross-realm trusted KDC can send an S4U2Proxy request with a PAC carrying a malformed client name to crash krb5kdc and deny authentication.

### CVE-2026-5704

- **Package:** `tar`
- **Installed:** `1.34+dfsg-1.2+deb12u1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-5704](https://security-tracker.debian.org/tracker/CVE-2026-5704)

A flaw was found in tar. A remote attacker could exploit this vulnerability by crafting a malicious archive, leading to hidden file injection with fully attacker-controlled content. This bypasses pre-extraction inspection mechanisms, potentially allowing an attacker to introduce malicious files onto a system without detection.

### CVE-2026-3184

- **Package:** `bsdutils`
- **Installed:** `1:2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-3184](https://security-tracker.debian.org/tracker/CVE-2026-3184)

A flaw was found in util-linux. Improper hostname canonicalization in the `login(1)` utility, when invoked with the `-h` option, can modify the supplied remote hostname before setting `PAM_RHOST`. A remote attacker could exploit this by providing a specially crafted hostname, potentially bypassing host-based Pluggable Authentication Modules (PAM) access control rules that rely on fully qualified domain names. This could lead to unauthorized access.

### CVE-2026-3184

- **Package:** `libblkid1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-3184](https://security-tracker.debian.org/tracker/CVE-2026-3184)

A flaw was found in util-linux. Improper hostname canonicalization in the `login(1)` utility, when invoked with the `-h` option, can modify the supplied remote hostname before setting `PAM_RHOST`. A remote attacker could exploit this by providing a specially crafted hostname, potentially bypassing host-based Pluggable Authentication Modules (PAM) access control rules that rely on fully qualified domain names. This could lead to unauthorized access.

### CVE-2026-3184

- **Package:** `libmount1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-3184](https://security-tracker.debian.org/tracker/CVE-2026-3184)

A flaw was found in util-linux. Improper hostname canonicalization in the `login(1)` utility, when invoked with the `-h` option, can modify the supplied remote hostname before setting `PAM_RHOST`. A remote attacker could exploit this by providing a specially crafted hostname, potentially bypassing host-based Pluggable Authentication Modules (PAM) access control rules that rely on fully qualified domain names. This could lead to unauthorized access.

### CVE-2026-3184

- **Package:** `libsmartcols1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-3184](https://security-tracker.debian.org/tracker/CVE-2026-3184)

A flaw was found in util-linux. Improper hostname canonicalization in the `login(1)` utility, when invoked with the `-h` option, can modify the supplied remote hostname before setting `PAM_RHOST`. A remote attacker could exploit this by providing a specially crafted hostname, potentially bypassing host-based Pluggable Authentication Modules (PAM) access control rules that rely on fully qualified domain names. This could lead to unauthorized access.

### CVE-2026-3184

- **Package:** `libuuid1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-3184](https://security-tracker.debian.org/tracker/CVE-2026-3184)

A flaw was found in util-linux. Improper hostname canonicalization in the `login(1)` utility, when invoked with the `-h` option, can modify the supplied remote hostname before setting `PAM_RHOST`. A remote attacker could exploit this by providing a specially crafted hostname, potentially bypassing host-based Pluggable Authentication Modules (PAM) access control rules that rely on fully qualified domain names. This could lead to unauthorized access.

### CVE-2026-3184

- **Package:** `mount`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-3184](https://security-tracker.debian.org/tracker/CVE-2026-3184)

A flaw was found in util-linux. Improper hostname canonicalization in the `login(1)` utility, when invoked with the `-h` option, can modify the supplied remote hostname before setting `PAM_RHOST`. A remote attacker could exploit this by providing a specially crafted hostname, potentially bypassing host-based Pluggable Authentication Modules (PAM) access control rules that rely on fully qualified domain names. This could lead to unauthorized access.

### CVE-2026-3184

- **Package:** `util-linux`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-3184](https://security-tracker.debian.org/tracker/CVE-2026-3184)

A flaw was found in util-linux. Improper hostname canonicalization in the `login(1)` utility, when invoked with the `-h` option, can modify the supplied remote hostname before setting `PAM_RHOST`. A remote attacker could exploit this by providing a specially crafted hostname, potentially bypassing host-based Pluggable Authentication Modules (PAM) access control rules that rely on fully qualified domain names. This could lead to unauthorized access.

### CVE-2026-3184

- **Package:** `util-linux-extra`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-3184](https://security-tracker.debian.org/tracker/CVE-2026-3184)

A flaw was found in util-linux. Improper hostname canonicalization in the `login(1)` utility, when invoked with the `-h` option, can modify the supplied remote hostname before setting `PAM_RHOST`. A remote attacker could exploit this by providing a specially crafted hostname, potentially bypassing host-based Pluggable Authentication Modules (PAM) access control rules that rely on fully qualified domain names. This could lead to unauthorized access.

### CVE-2025-7709

- **Package:** `libsqlite3-0`
- **Installed:** `3.40.1-2+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-7709](https://security-tracker.debian.org/tracker/CVE-2025-7709)

An integer overflow exists in the  FTS5 https://sqlite.org/fts5.html  extension. It occurs when the size of an array of tombstone pointers is calculated and truncated into a 32-bit integer. A pointer to partially controlled data can then be written out of bounds.

### CVE-2025-7709

- **Package:** `sqlite3`
- **Installed:** `3.40.1-2+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-7709](https://security-tracker.debian.org/tracker/CVE-2025-7709)

An integer overflow exists in the  FTS5 https://sqlite.org/fts5.html  extension. It occurs when the size of an array of tombstone pointers is calculated and truncated into a 32-bit integer. A pointer to partially controlled data can then be written out of bounds.

### CVE-2026-106552

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-106552](https://security-tracker.debian.org/tracker/CVE-2026-106552)

In sftp in OpenSSH before 10.6, a server can trigger directory traversal (causing files to be written to unintended locations) during a recursive copy operation.

### CVE-2026-6238

- **Package:** `libc-bin`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-6238](https://security-tracker.debian.org/tracker/CVE-2026-6238)

The deprecated functions ns_printrrf, ns_printrr and fp_nquery in the GNU C Library version 2.0.1 to version 2.43 fail to validate the RDATA content against the RDATA length in a DNS response when processing A6, CERT, LOC, TKEY or TSIG records, which may allow an attacker to craft a DNS response, causing a target application to crash or read uninitialized memory.  These functions are for application debugging only and hence not in the path of code executed by the DNS resolver.  Further, they have been deprecated since version 2.34 and should not be used by any new applications.  Applications should consider porting away from these interfaces since they may be removed in future versions.

### CVE-2026-6238

- **Package:** `libc6`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-6238](https://security-tracker.debian.org/tracker/CVE-2026-6238)

The deprecated functions ns_printrrf, ns_printrr and fp_nquery in the GNU C Library version 2.0.1 to version 2.43 fail to validate the RDATA content against the RDATA length in a DNS response when processing A6, CERT, LOC, TKEY or TSIG records, which may allow an attacker to craft a DNS response, causing a target application to crash or read uninitialized memory.  These functions are for application debugging only and hence not in the path of code executed by the DNS resolver.  Further, they have been deprecated since version 2.34 and should not be used by any new applications.  Applications should consider porting away from these interfaces since they may be removed in future versions.

### CVE-2025-15367

- **Package:** `python`
- **Installed:** `3.13.18`
- **Fixed in:** `3.15.0a6`
- **Reference:** [CVE-2025-15367](https://nvd.nist.gov/vuln/detail/CVE-2025-15367)

The poplib module, when passed a user-controlled command, can have
additional commands injected using newlines. Mitigation rejects commands
containing control characters.

### CVE-2026-77117

- **Package:** `libc-bin`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-77117](https://security-tracker.debian.org/tracker/CVE-2026-77117)

Converting crafted SHIFT_JISX0213 input to UCS-4 or the internal wide character encoding, for example with iconv, in the GNU C Library version 2.3 to 2.44 may result in the converter making no progress, causing the calling application to hang.  Some SHIFT_JISX0213 sequences decode to two code points.  If the output buffer has room for only the first one, the converter stores the second in the conversion state and returns E2BIG, but it never clears that pending character after emitting it on the next call.  The converter then keeps emitting the pending character without consuming further input, so an application that retries the conversion loops forever. The input must be attacker controlled and the application must convert it with an output buffer small enough to split the two code points. Only the SHIFT_JISX0213 character set is affected, which is not commonly used.  The related defect in the EUC_JISX0213 converter is tracked separately as CVE-2026-80489.

### CVE-2026-77117

- **Package:** `libc6`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-77117](https://security-tracker.debian.org/tracker/CVE-2026-77117)

Converting crafted SHIFT_JISX0213 input to UCS-4 or the internal wide character encoding, for example with iconv, in the GNU C Library version 2.3 to 2.44 may result in the converter making no progress, causing the calling application to hang.  Some SHIFT_JISX0213 sequences decode to two code points.  If the output buffer has room for only the first one, the converter stores the second in the conversion state and returns E2BIG, but it never clears that pending character after emitting it on the next call.  The converter then keeps emitting the pending character without consuming further input, so an application that retries the conversion loops forever. The input must be attacker controlled and the application must convert it with an output buffer small enough to split the two code points. Only the SHIFT_JISX0213 character set is affected, which is not commonly used.  The related defect in the EUC_JISX0213 converter is tracked separately as CVE-2026-80489.

### CVE-2026-80489

- **Package:** `libc-bin`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-80489](https://security-tracker.debian.org/tracker/CVE-2026-80489)

Converting crafted EUC_JISX0213 input to UCS-4 or the internal wide character encoding, for example with iconv, in the GNU C Library version 2.3 to 2.44 may result in the converter making no progress, causing the calling application to hang.  Some EUC_JISX0213 sequences decode to two code points.  If the output buffer has room for only the first one, the converter stores the second in the conversion state and returns E2BIG, but it never clears that pending character after emitting it on the next call.  The converter then keeps emitting the pending character without consuming further input, so an application that retries the conversion loops forever. The input must be attacker controlled and the application must convert it with an output buffer small enough to split the two code points. Only the EUC_JISX0213 character set is affected, which is not commonly used.  The related defect in SHIFT_JISX0213 converter is tracked separately as CVE-2026-77117.

### CVE-2026-80489

- **Package:** `libc6`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-80489](https://security-tracker.debian.org/tracker/CVE-2026-80489)

Converting crafted EUC_JISX0213 input to UCS-4 or the internal wide character encoding, for example with iconv, in the GNU C Library version 2.3 to 2.44 may result in the converter making no progress, causing the calling application to hang.  Some EUC_JISX0213 sequences decode to two code points.  If the output buffer has room for only the first one, the converter stores the second in the conversion state and returns E2BIG, but it never clears that pending character after emitting it on the next call.  The converter then keeps emitting the pending character without consuming further input, so an application that retries the conversion loops forever. The input must be attacker controlled and the application must convert it with an output buffer small enough to split the two code points. Only the EUC_JISX0213 character set is affected, which is not commonly used.  The related defect in SHIFT_JISX0213 converter is tracked separately as CVE-2026-77117.

### CVE-2026-54411

- **Package:** `libpam-modules`
- **Installed:** `1.5.2-6+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-54411](https://security-tracker.debian.org/tracker/CVE-2026-54411)

Linux-PAM through 1.7.2 contains an observable timing discrepancy (CWE-208) in the pam_userdb module's plaintext-password comparison path in modules/pam_userdb/pam_userdb.c that allows a local or network-adjacent attacker able to repeatedly drive authentication through a calling service to recover the plaintext password of a target account by measuring response-timing differences.

### CVE-2026-54411

- **Package:** `libpam-modules-bin`
- **Installed:** `1.5.2-6+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-54411](https://security-tracker.debian.org/tracker/CVE-2026-54411)

Linux-PAM through 1.7.2 contains an observable timing discrepancy (CWE-208) in the pam_userdb module's plaintext-password comparison path in modules/pam_userdb/pam_userdb.c that allows a local or network-adjacent attacker able to repeatedly drive authentication through a calling service to recover the plaintext password of a target account by measuring response-timing differences.

### CVE-2026-54411

- **Package:** `libpam-runtime`
- **Installed:** `1.5.2-6+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-54411](https://security-tracker.debian.org/tracker/CVE-2026-54411)

Linux-PAM through 1.7.2 contains an observable timing discrepancy (CWE-208) in the pam_userdb module's plaintext-password comparison path in modules/pam_userdb/pam_userdb.c that allows a local or network-adjacent attacker able to repeatedly drive authentication through a calling service to recover the plaintext password of a target account by measuring response-timing differences.

### CVE-2026-54411

- **Package:** `libpam0g`
- **Installed:** `1.5.2-6+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-54411](https://security-tracker.debian.org/tracker/CVE-2026-54411)

Linux-PAM through 1.7.2 contains an observable timing discrepancy (CWE-208) in the pam_userdb module's plaintext-password comparison path in modules/pam_userdb/pam_userdb.c that allows a local or network-adjacent attacker able to repeatedly drive authentication through a calling service to recover the plaintext password of a target account by measuring response-timing differences.

### CVE-2026-60001

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-60001](https://security-tracker.debian.org/tracker/CVE-2026-60001)

sshd in OpenSSH before 10.4 does not always honor the minimum authentication delay.

### CVE-2026-8674

- **Package:** `libc-bin`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-8674](https://security-tracker.debian.org/tracker/CVE-2026-8674)

Initializing the DNS stub resolver from an /etc/resolv.conf file, or a LOCALDOMAIN environment variable, whose search list contains a domain of roughly 200 characters or more in the GNU C Library version 2.26 to 2.44 results in an assertion failure which aborts the process.  The resolver truncates the search list when copying it into the fixed-size _res.defdname buffer, then asserts that the copy is consistent with the full configuration.  The consistency check compared against the wrong size and did not handle a first entry that does not fit, so a correctly truncated list failed the assertion.  Any process that resolves names through the library is affected, including long-running processes that reload /etc/resolv.conf on the next query after it changes.  Search domains are commonly written to /etc/resolv.conf from data received over DHCP or from a VPN server, so an attacker on the local network may be able to trigger this without privileges on the target system, subject to validation by the network configuration software.

### CVE-2026-8674

- **Package:** `libc6`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-8674](https://security-tracker.debian.org/tracker/CVE-2026-8674)

Initializing the DNS stub resolver from an /etc/resolv.conf file, or a LOCALDOMAIN environment variable, whose search list contains a domain of roughly 200 characters or more in the GNU C Library version 2.26 to 2.44 results in an assertion failure which aborts the process.  The resolver truncates the search list when copying it into the fixed-size _res.defdname buffer, then asserts that the copy is consistent with the full configuration.  The consistency check compared against the wrong size and did not handle a first entry that does not fit, so a correctly truncated list failed the assertion.  Any process that resolves names through the library is affected, including long-running processes that reload /etc/resolv.conf on the next query after it changes.  Search domains are commonly written to /etc/resolv.conf from data received over DHCP or from a VPN server, so an attacker on the local network may be able to trigger this without privileges on the target system, subject to validation by the network configuration software.

### CVE-2026-27171

- **Package:** `zlib1g`
- **Installed:** `1:1.2.13.dfsg-1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-27171](https://security-tracker.debian.org/tracker/CVE-2026-27171)

zlib before 1.3.2 allows CPU consumption via crc32_combine64 and crc32_combine_gen64 because x2nmodp can do right shifts within a loop that has no termination condition.

### CVE-2026-59996

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-59996](https://security-tracker.debian.org/tracker/CVE-2026-59996)

scp in OpenSSH before 10.4 may place a file in the parent directory of an intended directory when the copy occurs between two remote destinations.

### CVE-2026-59995

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-59995](https://security-tracker.debian.org/tracker/CVE-2026-59995)

sftp in OpenSSH before 10.4 does not properly constrain the location of downloaded files when "sftp server:/path ." is used with an attacker-controlled server.

### CVE-2024-10041

- **Package:** `libpam-modules`
- **Installed:** `1.5.2-6+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2024-10041](https://security-tracker.debian.org/tracker/CVE-2024-10041)

A vulnerability was found in PAM. The secret information is stored in memory, where the attacker can trigger the victim program to execute by sending characters to its standard input (stdin). As this occurs, the attacker can train the branch predictor to execute an ROP chain speculatively. This flaw could result in leaked passwords, such as those found in /etc/shadow while performing authentications.

### CVE-2024-10041

- **Package:** `libpam-modules-bin`
- **Installed:** `1.5.2-6+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2024-10041](https://security-tracker.debian.org/tracker/CVE-2024-10041)

A vulnerability was found in PAM. The secret information is stored in memory, where the attacker can trigger the victim program to execute by sending characters to its standard input (stdin). As this occurs, the attacker can train the branch predictor to execute an ROP chain speculatively. This flaw could result in leaked passwords, such as those found in /etc/shadow while performing authentications.

### CVE-2024-10041

- **Package:** `libpam-runtime`
- **Installed:** `1.5.2-6+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2024-10041](https://security-tracker.debian.org/tracker/CVE-2024-10041)

A vulnerability was found in PAM. The secret information is stored in memory, where the attacker can trigger the victim program to execute by sending characters to its standard input (stdin). As this occurs, the attacker can train the branch predictor to execute an ROP chain speculatively. This flaw could result in leaked passwords, such as those found in /etc/shadow while performing authentications.

### CVE-2024-10041

- **Package:** `libpam0g`
- **Installed:** `1.5.2-6+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2024-10041](https://security-tracker.debian.org/tracker/CVE-2024-10041)

A vulnerability was found in PAM. The secret information is stored in memory, where the attacker can trigger the victim program to execute by sending characters to its standard input (stdin). As this occurs, the attacker can train the branch predictor to execute an ROP chain speculatively. This flaw could result in leaked passwords, such as those found in /etc/shadow while performing authentications.

### CVE-2026-6791

- **Package:** `libc-bin`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-6791](https://security-tracker.debian.org/tracker/CVE-2026-6791)

When expanding paths that begin with a tilde (~) followed by a username, the internal parse_tilde function extracts the username to determine the user's home directory.  The implementation allocates memory for this username directly on the stack using the strndupa macro. Because the size of this allocation was determined by the length of the user-supplied input without any bounds checks, passing an excessively long username e.g. thousands of characters, forces the thread to exhaust its stack space. Thus if an application passes untrusted, attacker-controlled input to the wordexp function, an attacker can trigger a stack clash.

### CVE-2026-6791

- **Package:** `libc6`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-6791](https://security-tracker.debian.org/tracker/CVE-2026-6791)

When expanding paths that begin with a tilde (~) followed by a username, the internal parse_tilde function extracts the username to determine the user's home directory.  The implementation allocates memory for this username directly on the stack using the strndupa macro. Because the size of this allocation was determined by the length of the user-supplied input without any bounds checks, passing an excessively long username e.g. thousands of characters, forces the thread to exhaust its stack space. Thus if an application passes untrusted, attacker-controlled input to the wordexp function, an attacker can trigger a stack clash.

### CVE-2026-19542

- **Package:** `libc-bin`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-19542](https://security-tracker.debian.org/tracker/CVE-2026-19542)

Calling tdelete on a sufficiently deep tree in the GNU C Library version 2.1 to 2.44 may write one pointer past the end of an alloca-allocated array on the stack, which may crash the application.  The tdelete implementation keeps an explicit stack of parent nodes for rebalancing, which is grown as needed while descending the tree.  Two rebalancing branches push an additional entry without checking the capacity, and write past the array when the stack is exactly full. Triggering this requires a node at a depth of exactly 40 (or 40 plus a multiple of 20), which implies a tree with at least a million nodes, so an attacker must drive a large number of insertions and deletions through an application that uses tsearch and tdelete.  The written value is a pointer into a tree node and is not directly attacker controlled.  No affected application in common distributions has been identified.

### CVE-2026-19542

- **Package:** `libc6`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-19542](https://security-tracker.debian.org/tracker/CVE-2026-19542)

Calling tdelete on a sufficiently deep tree in the GNU C Library version 2.1 to 2.44 may write one pointer past the end of an alloca-allocated array on the stack, which may crash the application.  The tdelete implementation keeps an explicit stack of parent nodes for rebalancing, which is grown as needed while descending the tree.  Two rebalancing branches push an additional entry without checking the capacity, and write past the array when the stack is exactly full. Triggering this requires a node at a depth of exactly 40 (or 40 plus a multiple of 20), which implies a tree with at least a million nodes, so an attacker must drive a large number of insertions and deletions through an application that uses tsearch and tdelete.  The written value is a pointer into a tree node and is not directly attacker controlled.  No affected application in common distributions has been identified.

### CVE-2026-89092

- **Package:** `libc-bin`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-89092](https://security-tracker.debian.org/tracker/CVE-2026-89092)

The nscd service in the GNU C Library 2.3.4 onwards may crash due to a  stack overflow when a malicious DNS server returns too large a response  for a DNS query, resulting in degraded DNS resolution for the system.    Exploitation of this bug needs a system that has nscd enabled and using  an untrusted DNS server for name resolution, with the compromised DNS  server being capable of processing records large enough to result in a  stack overflow in an nscd thread stack.  During experimentation, bind 9  was unable to handle large records, but that could change in future or  with a different name server.  In typical installations, nscd is  executed in an isolated context as its own user without a shell, due to  which any compromise of that service is isolated.    There is a remote possibility of nscd cache corruption if an attacker  manages to get the stack pointer into a desired point in the heap,  potentially resulting in other caches in nscd being overwritten with  corrupt data through the stack overflow, until the buggy code path  eventually results in a crash.    Finally, a crash in nscd may result in performance degradation when  resolving names, but it does not result in a denial of service.

### CVE-2026-89092

- **Package:** `libc6`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-89092](https://security-tracker.debian.org/tracker/CVE-2026-89092)

The nscd service in the GNU C Library 2.3.4 onwards may crash due to a  stack overflow when a malicious DNS server returns too large a response  for a DNS query, resulting in degraded DNS resolution for the system.    Exploitation of this bug needs a system that has nscd enabled and using  an untrusted DNS server for name resolution, with the compromised DNS  server being capable of processing records large enough to result in a  stack overflow in an nscd thread stack.  During experimentation, bind 9  was unable to handle large records, but that could change in future or  with a different name server.  In typical installations, nscd is  executed in an isolated context as its own user without a shell, due to  which any compromise of that service is isolated.    There is a remote possibility of nscd cache corruption if an attacker  manages to get the stack pointer into a desired point in the heap,  potentially resulting in other caches in nscd being overwritten with  corrupt data through the stack overflow, until the buggy code path  eventually results in a crash.    Finally, a crash in nscd may result in performance degradation when  resolving names, but it does not result in a denial of service.

### CVE-2026-106585

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-106585](https://security-tracker.debian.org/tracker/CVE-2026-106585)

In sshd and ssh in OpenSSH before 10.6, there is no check for whether the maximum packet length is exceeded during decompression of highly compressed data.

### CVE-2026-59998

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-59998](https://security-tracker.debian.org/tracker/CVE-2026-59998)

sshd in OpenSSH before 10.4 has an undocumented security-relevant behavior: GSSAPIStrictAcceptorCheck has no value if the server is in Windows Active Directory.

### CVE-2026-11822

- **Package:** `libsqlite3-0`
- **Installed:** `3.40.1-2+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-11822](https://security-tracker.debian.org/tracker/CVE-2026-11822)

SQLite before 3.53.2 contains an out-of-bounds read vulnerability in the FTS5 full-text search extension that allows attackers to crash the process by supplying a crafted database with a malformed FTS5 leaf page. Attackers can set an oversized term length in the leaf page so that fts5LeafSeek() reads past the end of the page buffer while comparing terms during an FTS5 MATCH query, in applications compiled with SQLITE_ENABLE_FTS5.

### CVE-2026-11822

- **Package:** `sqlite3`
- **Installed:** `3.40.1-2+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-11822](https://security-tracker.debian.org/tracker/CVE-2026-11822)

SQLite before 3.53.2 contains an out-of-bounds read vulnerability in the FTS5 full-text search extension that allows attackers to crash the process by supplying a crafted database with a malformed FTS5 leaf page. Attackers can set an oversized term length in the leaf page so that fts5LeafSeek() reads past the end of the page buffer while comparing terms during an FTS5 MATCH query, in applications compiled with SQLITE_ENABLE_FTS5.

### CVE-2025-6141

- **Package:** `libncursesw6`
- **Installed:** `6.4-4`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-6141](https://security-tracker.debian.org/tracker/CVE-2025-6141)

A vulnerability has been found in GNU ncurses up to 6.5-20250322 and classified as problematic. This vulnerability affects the function postprocess_termcap of the file tinfo/parse_entry.c. The manipulation leads to stack-based buffer overflow. The attack needs to be approached locally. Upgrading to version 6.5-20250329 is able to address this issue. It is recommended to upgrade the affected component.

### CVE-2025-6141

- **Package:** `libtinfo6`
- **Installed:** `6.4-4`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-6141](https://security-tracker.debian.org/tracker/CVE-2025-6141)

A vulnerability has been found in GNU ncurses up to 6.5-20250322 and classified as problematic. This vulnerability affects the function postprocess_termcap of the file tinfo/parse_entry.c. The manipulation leads to stack-based buffer overflow. The attack needs to be approached locally. Upgrading to version 6.5-20250329 is able to address this issue. It is recommended to upgrade the affected component.

### CVE-2025-6141

- **Package:** `ncurses-base`
- **Installed:** `6.4-4`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-6141](https://security-tracker.debian.org/tracker/CVE-2025-6141)

A vulnerability has been found in GNU ncurses up to 6.5-20250322 and classified as problematic. This vulnerability affects the function postprocess_termcap of the file tinfo/parse_entry.c. The manipulation leads to stack-based buffer overflow. The attack needs to be approached locally. Upgrading to version 6.5-20250329 is able to address this issue. It is recommended to upgrade the affected component.

### CVE-2025-6141

- **Package:** `ncurses-bin`
- **Installed:** `6.4-4`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-6141](https://security-tracker.debian.org/tracker/CVE-2025-6141)

A vulnerability has been found in GNU ncurses up to 6.5-20250322 and classified as problematic. This vulnerability affects the function postprocess_termcap of the file tinfo/parse_entry.c. The manipulation leads to stack-based buffer overflow. The attack needs to be approached locally. Upgrading to version 6.5-20250329 is able to address this issue. It is recommended to upgrade the affected component.

### CVE-2025-30258

- **Package:** `gpgv`
- **Installed:** `2.2.40-1.1+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-30258](https://security-tracker.debian.org/tracker/CVE-2025-30258)

In GnuPG before 2.5.5, if a user chooses to import a certificate with certain crafted subkey data that lacks a valid backsig or that has incorrect usage flags, the user loses the ability to verify signatures made from certain other signing keys, aka a "verification DoS."

### CVE-2026-59997

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-59997](https://security-tracker.debian.org/tracker/CVE-2026-59997)

internal-sftp in sshd in OpenSSH before 10.4 recognizes only the first 9 command-line arguments, which can be important if a later command-line argument would have helped to ensure the intended security properties of an SFTP connection.

### CVE-2026-15534

- **Package:** `perl-base`
- **Installed:** `5.36.0-7+deb12u4`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-15534](https://security-tracker.debian.org/tracker/CVE-2026-15534)

Perl versions through 5.45.1 have out-of-bounds heap reads and writes during regular expression matching via an undersized superlinear cache in S_regmatch.  The regex engine's superlinear cache holds one bit per subject position for each participating WHILEM node, so the bit count is the subject length plus one times the number of nodes. Nothing checks that product for positive overflow of the signed 32-bit count: a 286331153 byte subject matched against a pattern with 15 participating nodes stores the count as 14, leaving a two byte cache. The cache is then indexed from the real match position and node number, so reads go past the end of the allocation, and on failure CACHEsayNO sets a bit past it.  A caller that matches an attacker controlled subject of this size against a pattern of this shape can crash the process or corrupt heap memory.

### CVE-2026-13757

- **Package:** `libp11-kit0`
- **Installed:** `0.24.1-2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-13757](https://security-tracker.debian.org/tracker/CVE-2026-13757)

A flaw was found in p11-kit. The RPC message attribute parsing functions p11_rpc_message_get_attribute() and p11_rpc_message_get_attribute_array_value() form a mutually-recursive call chain with no recursion depth limit when processing nested CKA_WRAP_TEMPLATE, CKA_UNWRAP_TEMPLATE, and CKA_DERIVE_TEMPLATE attributes. An unauthenticated attacker with local access to the p11-kit RPC Unix domain socket can send a specially crafted request with deeply nested template attributes, causing stack exhaustion and crashing the p11-kit server process and its dependent services.

### CVE-2026-15059

- **Package:** `libsystemd0`
- **Installed:** `252.39-1~deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-15059](https://security-tracker.debian.org/tracker/CVE-2026-15059)

Local unprivileged users can terminate arbitrary local processes via a systemd-oomd IPC API due to a missing path traversal validation.

### CVE-2026-15059

- **Package:** `libudev1`
- **Installed:** `252.39-1~deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-15059](https://security-tracker.debian.org/tracker/CVE-2026-15059)

Local unprivileged users can terminate arbitrary local processes via a systemd-oomd IPC API due to a missing path traversal validation.

### CVE-2026-50812

- **Package:** `libsqlite3-0`
- **Installed:** `3.40.1-2+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-50812](https://security-tracker.debian.org/tracker/CVE-2026-50812)

A NULL pointer dereference in the SQLite Session Extension in SQLite 3.53.1 and SQLite trunk builds before check-in e807d4e3798efd53 allows an attacker who can supply a malformed changeset blob to cause a denial of service. The issue occurs when sqlite3changeset_apply_v3() applies a corrupt changeset and reaches sqlite3_value_type() with a NULL sqlite3_value pointer.

### CVE-2026-50812

- **Package:** `sqlite3`
- **Installed:** `3.40.1-2+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-50812](https://security-tracker.debian.org/tracker/CVE-2026-50812)

A NULL pointer dereference in the SQLite Session Extension in SQLite 3.53.1 and SQLite trunk builds before check-in e807d4e3798efd53 allows an attacker who can supply a malformed changeset blob to cause a denial of service. The issue occurs when sqlite3changeset_apply_v3() applies a corrupt changeset and reaches sqlite3_value_type() with a NULL sqlite3_value pointer.

### CVE-2026-50813

- **Package:** `libsqlite3-0`
- **Installed:** `3.40.1-2+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-50813](https://security-tracker.debian.org/tracker/CVE-2026-50813)

An issue in SQLite before Fossil check-in 869a51ae84df allows a local attacker to obtain sensitive information via the Session Extension changeset concat/changegroup merge path

### CVE-2026-50813

- **Package:** `sqlite3`
- **Installed:** `3.40.1-2+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-50813](https://security-tracker.debian.org/tracker/CVE-2026-50813)

An issue in SQLite before Fossil check-in 869a51ae84df allows a local attacker to obtain sensitive information via the Session Extension changeset concat/changegroup merge path

### CVE-2026-54371

- **Package:** `libattr1`
- **Installed:** `1:2.5.1-4`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-54371](https://security-tracker.debian.org/tracker/CVE-2026-54371)

attr before version 2.6.0 contains a symlink traversal vulnerability in the getfattr and setfattr utilities that allows local attackers to escalate privileges by replacing a pathname component with a symbolic link during directory hierarchy traversal. Attackers who control a pathname component can redirect getfattr and setfattr operations to arbitrary files by substituting a symlink, leading to local privilege escalation when getfattr or setfattr is invoked by a privileged process over an attacker-controlled path.

### CVE-2026-73282

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-73282](https://security-tracker.debian.org/tracker/CVE-2026-73282)

In ssh in OpenSSH before 10.5, a use-after-free for realloc data can occur if a certain pair of remote-forwarding operations are concurrent.

### CVE-2026-13595

- **Package:** `bsdutils`
- **Installed:** `1:2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-13595](https://security-tracker.debian.org/tracker/CVE-2026-13595)

A flaw was found in the libblkid library of util-linux. During nested partition probing, the BSD, Minix, Solaris x86, and UnixWare partition probers cache a raw pointer to a parent partition entry in a dynamically allocated array. When subsequent partition additions cause the array to be reallocated, this pointer becomes stale, leading to a heap use-after-free read. An attacker who can present a crafted block device image (for example, via USB insertion or a loop-mounted disk image) can trigger this flaw without user interaction, as libblkid is invoked automatically by udev/udisks as root on block-device hot-plug events. This could lead to limited information disclosure or denial of service.

### CVE-2026-13595

- **Package:** `libblkid1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-13595](https://security-tracker.debian.org/tracker/CVE-2026-13595)

A flaw was found in the libblkid library of util-linux. During nested partition probing, the BSD, Minix, Solaris x86, and UnixWare partition probers cache a raw pointer to a parent partition entry in a dynamically allocated array. When subsequent partition additions cause the array to be reallocated, this pointer becomes stale, leading to a heap use-after-free read. An attacker who can present a crafted block device image (for example, via USB insertion or a loop-mounted disk image) can trigger this flaw without user interaction, as libblkid is invoked automatically by udev/udisks as root on block-device hot-plug events. This could lead to limited information disclosure or denial of service.

### CVE-2026-13595

- **Package:** `libmount1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-13595](https://security-tracker.debian.org/tracker/CVE-2026-13595)

A flaw was found in the libblkid library of util-linux. During nested partition probing, the BSD, Minix, Solaris x86, and UnixWare partition probers cache a raw pointer to a parent partition entry in a dynamically allocated array. When subsequent partition additions cause the array to be reallocated, this pointer becomes stale, leading to a heap use-after-free read. An attacker who can present a crafted block device image (for example, via USB insertion or a loop-mounted disk image) can trigger this flaw without user interaction, as libblkid is invoked automatically by udev/udisks as root on block-device hot-plug events. This could lead to limited information disclosure or denial of service.

### CVE-2026-13595

- **Package:** `libsmartcols1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-13595](https://security-tracker.debian.org/tracker/CVE-2026-13595)

A flaw was found in the libblkid library of util-linux. During nested partition probing, the BSD, Minix, Solaris x86, and UnixWare partition probers cache a raw pointer to a parent partition entry in a dynamically allocated array. When subsequent partition additions cause the array to be reallocated, this pointer becomes stale, leading to a heap use-after-free read. An attacker who can present a crafted block device image (for example, via USB insertion or a loop-mounted disk image) can trigger this flaw without user interaction, as libblkid is invoked automatically by udev/udisks as root on block-device hot-plug events. This could lead to limited information disclosure or denial of service.

### CVE-2026-13595

- **Package:** `libuuid1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-13595](https://security-tracker.debian.org/tracker/CVE-2026-13595)

A flaw was found in the libblkid library of util-linux. During nested partition probing, the BSD, Minix, Solaris x86, and UnixWare partition probers cache a raw pointer to a parent partition entry in a dynamically allocated array. When subsequent partition additions cause the array to be reallocated, this pointer becomes stale, leading to a heap use-after-free read. An attacker who can present a crafted block device image (for example, via USB insertion or a loop-mounted disk image) can trigger this flaw without user interaction, as libblkid is invoked automatically by udev/udisks as root on block-device hot-plug events. This could lead to limited information disclosure or denial of service.

### CVE-2026-13595

- **Package:** `mount`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-13595](https://security-tracker.debian.org/tracker/CVE-2026-13595)

A flaw was found in the libblkid library of util-linux. During nested partition probing, the BSD, Minix, Solaris x86, and UnixWare partition probers cache a raw pointer to a parent partition entry in a dynamically allocated array. When subsequent partition additions cause the array to be reallocated, this pointer becomes stale, leading to a heap use-after-free read. An attacker who can present a crafted block device image (for example, via USB insertion or a loop-mounted disk image) can trigger this flaw without user interaction, as libblkid is invoked automatically by udev/udisks as root on block-device hot-plug events. This could lead to limited information disclosure or denial of service.

### CVE-2026-13595

- **Package:** `util-linux`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-13595](https://security-tracker.debian.org/tracker/CVE-2026-13595)

A flaw was found in the libblkid library of util-linux. During nested partition probing, the BSD, Minix, Solaris x86, and UnixWare partition probers cache a raw pointer to a parent partition entry in a dynamically allocated array. When subsequent partition additions cause the array to be reallocated, this pointer becomes stale, leading to a heap use-after-free read. An attacker who can present a crafted block device image (for example, via USB insertion or a loop-mounted disk image) can trigger this flaw without user interaction, as libblkid is invoked automatically by udev/udisks as root on block-device hot-plug events. This could lead to limited information disclosure or denial of service.

### CVE-2026-13595

- **Package:** `util-linux-extra`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-13595](https://security-tracker.debian.org/tracker/CVE-2026-13595)

A flaw was found in the libblkid library of util-linux. During nested partition probing, the BSD, Minix, Solaris x86, and UnixWare partition probers cache a raw pointer to a parent partition entry in a dynamically allocated array. When subsequent partition additions cause the array to be reallocated, this pointer becomes stale, leading to a heap use-after-free read. An attacker who can present a crafted block device image (for example, via USB insertion or a loop-mounted disk image) can trigger this flaw without user interaction, as libblkid is invoked automatically by udev/udisks as root on block-device hot-plug events. This could lead to limited information disclosure or denial of service.

### CVE-2026-27456

- **Package:** `bsdutils`
- **Installed:** `1:2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-27456](https://security-tracker.debian.org/tracker/CVE-2026-27456)

util-linux is a random collection of Linux utilities. Prior to version 2.41.4, a TOCTOU (Time-of-Check-Time-of-Use) vulnerability has been identified in the SUID binary /usr/bin/mount from util-linux. The mount binary, when setting up loop devices, validates the source file path with user privileges via fork() + setuid() + realpath(), but subsequently re-canonicalizes and opens it with root privileges (euid=0) without verifying that the path has not been replaced between both operations. Neither O_NOFOLLOW, nor inode comparison, nor post-open fstat() are employed. This allows a local unprivileged user to replace the source file with a symlink pointing to any root-owned file or device during the race window, causing the SUID binary to open and mount it as root. Exploitation requires an /etc/fstab entry with user,loop options whose path points to a directory where the attacker has write permission, and that /usr/bin/mount has the SUID bit set (the default configuration on virtually all Linux distributions). The impact is unauthorized read access to root-protected files and block devices, including backup images, disk volumes, and any file containing a valid filesystem. This issue has been patched in version 2.41.4.

### CVE-2026-27456

- **Package:** `libblkid1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-27456](https://security-tracker.debian.org/tracker/CVE-2026-27456)

util-linux is a random collection of Linux utilities. Prior to version 2.41.4, a TOCTOU (Time-of-Check-Time-of-Use) vulnerability has been identified in the SUID binary /usr/bin/mount from util-linux. The mount binary, when setting up loop devices, validates the source file path with user privileges via fork() + setuid() + realpath(), but subsequently re-canonicalizes and opens it with root privileges (euid=0) without verifying that the path has not been replaced between both operations. Neither O_NOFOLLOW, nor inode comparison, nor post-open fstat() are employed. This allows a local unprivileged user to replace the source file with a symlink pointing to any root-owned file or device during the race window, causing the SUID binary to open and mount it as root. Exploitation requires an /etc/fstab entry with user,loop options whose path points to a directory where the attacker has write permission, and that /usr/bin/mount has the SUID bit set (the default configuration on virtually all Linux distributions). The impact is unauthorized read access to root-protected files and block devices, including backup images, disk volumes, and any file containing a valid filesystem. This issue has been patched in version 2.41.4.

### CVE-2026-27456

- **Package:** `libmount1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-27456](https://security-tracker.debian.org/tracker/CVE-2026-27456)

util-linux is a random collection of Linux utilities. Prior to version 2.41.4, a TOCTOU (Time-of-Check-Time-of-Use) vulnerability has been identified in the SUID binary /usr/bin/mount from util-linux. The mount binary, when setting up loop devices, validates the source file path with user privileges via fork() + setuid() + realpath(), but subsequently re-canonicalizes and opens it with root privileges (euid=0) without verifying that the path has not been replaced between both operations. Neither O_NOFOLLOW, nor inode comparison, nor post-open fstat() are employed. This allows a local unprivileged user to replace the source file with a symlink pointing to any root-owned file or device during the race window, causing the SUID binary to open and mount it as root. Exploitation requires an /etc/fstab entry with user,loop options whose path points to a directory where the attacker has write permission, and that /usr/bin/mount has the SUID bit set (the default configuration on virtually all Linux distributions). The impact is unauthorized read access to root-protected files and block devices, including backup images, disk volumes, and any file containing a valid filesystem. This issue has been patched in version 2.41.4.

### CVE-2026-27456

- **Package:** `libsmartcols1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-27456](https://security-tracker.debian.org/tracker/CVE-2026-27456)

util-linux is a random collection of Linux utilities. Prior to version 2.41.4, a TOCTOU (Time-of-Check-Time-of-Use) vulnerability has been identified in the SUID binary /usr/bin/mount from util-linux. The mount binary, when setting up loop devices, validates the source file path with user privileges via fork() + setuid() + realpath(), but subsequently re-canonicalizes and opens it with root privileges (euid=0) without verifying that the path has not been replaced between both operations. Neither O_NOFOLLOW, nor inode comparison, nor post-open fstat() are employed. This allows a local unprivileged user to replace the source file with a symlink pointing to any root-owned file or device during the race window, causing the SUID binary to open and mount it as root. Exploitation requires an /etc/fstab entry with user,loop options whose path points to a directory where the attacker has write permission, and that /usr/bin/mount has the SUID bit set (the default configuration on virtually all Linux distributions). The impact is unauthorized read access to root-protected files and block devices, including backup images, disk volumes, and any file containing a valid filesystem. This issue has been patched in version 2.41.4.

### CVE-2026-27456

- **Package:** `libuuid1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-27456](https://security-tracker.debian.org/tracker/CVE-2026-27456)

util-linux is a random collection of Linux utilities. Prior to version 2.41.4, a TOCTOU (Time-of-Check-Time-of-Use) vulnerability has been identified in the SUID binary /usr/bin/mount from util-linux. The mount binary, when setting up loop devices, validates the source file path with user privileges via fork() + setuid() + realpath(), but subsequently re-canonicalizes and opens it with root privileges (euid=0) without verifying that the path has not been replaced between both operations. Neither O_NOFOLLOW, nor inode comparison, nor post-open fstat() are employed. This allows a local unprivileged user to replace the source file with a symlink pointing to any root-owned file or device during the race window, causing the SUID binary to open and mount it as root. Exploitation requires an /etc/fstab entry with user,loop options whose path points to a directory where the attacker has write permission, and that /usr/bin/mount has the SUID bit set (the default configuration on virtually all Linux distributions). The impact is unauthorized read access to root-protected files and block devices, including backup images, disk volumes, and any file containing a valid filesystem. This issue has been patched in version 2.41.4.

### CVE-2026-27456

- **Package:** `mount`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-27456](https://security-tracker.debian.org/tracker/CVE-2026-27456)

util-linux is a random collection of Linux utilities. Prior to version 2.41.4, a TOCTOU (Time-of-Check-Time-of-Use) vulnerability has been identified in the SUID binary /usr/bin/mount from util-linux. The mount binary, when setting up loop devices, validates the source file path with user privileges via fork() + setuid() + realpath(), but subsequently re-canonicalizes and opens it with root privileges (euid=0) without verifying that the path has not been replaced between both operations. Neither O_NOFOLLOW, nor inode comparison, nor post-open fstat() are employed. This allows a local unprivileged user to replace the source file with a symlink pointing to any root-owned file or device during the race window, causing the SUID binary to open and mount it as root. Exploitation requires an /etc/fstab entry with user,loop options whose path points to a directory where the attacker has write permission, and that /usr/bin/mount has the SUID bit set (the default configuration on virtually all Linux distributions). The impact is unauthorized read access to root-protected files and block devices, including backup images, disk volumes, and any file containing a valid filesystem. This issue has been patched in version 2.41.4.

### CVE-2026-27456

- **Package:** `util-linux`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-27456](https://security-tracker.debian.org/tracker/CVE-2026-27456)

util-linux is a random collection of Linux utilities. Prior to version 2.41.4, a TOCTOU (Time-of-Check-Time-of-Use) vulnerability has been identified in the SUID binary /usr/bin/mount from util-linux. The mount binary, when setting up loop devices, validates the source file path with user privileges via fork() + setuid() + realpath(), but subsequently re-canonicalizes and opens it with root privileges (euid=0) without verifying that the path has not been replaced between both operations. Neither O_NOFOLLOW, nor inode comparison, nor post-open fstat() are employed. This allows a local unprivileged user to replace the source file with a symlink pointing to any root-owned file or device during the race window, causing the SUID binary to open and mount it as root. Exploitation requires an /etc/fstab entry with user,loop options whose path points to a directory where the attacker has write permission, and that /usr/bin/mount has the SUID bit set (the default configuration on virtually all Linux distributions). The impact is unauthorized read access to root-protected files and block devices, including backup images, disk volumes, and any file containing a valid filesystem. This issue has been patched in version 2.41.4.

### CVE-2026-27456

- **Package:** `util-linux-extra`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-27456](https://security-tracker.debian.org/tracker/CVE-2026-27456)

util-linux is a random collection of Linux utilities. Prior to version 2.41.4, a TOCTOU (Time-of-Check-Time-of-Use) vulnerability has been identified in the SUID binary /usr/bin/mount from util-linux. The mount binary, when setting up loop devices, validates the source file path with user privileges via fork() + setuid() + realpath(), but subsequently re-canonicalizes and opens it with root privileges (euid=0) without verifying that the path has not been replaced between both operations. Neither O_NOFOLLOW, nor inode comparison, nor post-open fstat() are employed. This allows a local unprivileged user to replace the source file with a symlink pointing to any root-owned file or device during the race window, causing the SUID binary to open and mount it as root. Exploitation requires an /etc/fstab entry with user,loop options whose path points to a directory where the attacker has write permission, and that /usr/bin/mount has the SUID bit set (the default configuration on virtually all Linux distributions). The impact is unauthorized read access to root-protected files and block devices, including backup images, disk volumes, and any file containing a valid filesystem. This issue has been patched in version 2.41.4.

### CVE-2026-18374

- **Package:** `libc-bin`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-18374](https://security-tracker.debian.org/tracker/CVE-2026-18374)

Passing an effectively empty string to the `,ccs=` syntax extension of the mode argument in the `fopen` function in the GNU C Library version 2.45 or earlier may result in a heap buffer overflow when the mode string input to the function is attacker controlled.    This usage pattern is not seen in applications in common GNU/Linux distributions and applications that process user-supplied values for `ccs` should not pass them through without validation.

### CVE-2026-18374

- **Package:** `libc6`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-18374](https://security-tracker.debian.org/tracker/CVE-2026-18374)

Passing an effectively empty string to the `,ccs=` syntax extension of the mode argument in the `fopen` function in the GNU C Library version 2.45 or earlier may result in a heap buffer overflow when the mode string input to the function is attacker controlled.    This usage pattern is not seen in applications in common GNU/Linux distributions and applications that process user-supplied values for `ccs` should not pass them through without validation.

### CVE-2026-18508

- **Package:** `tar`
- **Installed:** `1.34+dfsg-1.2+deb12u1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-18508](https://security-tracker.debian.org/tracker/CVE-2026-18508)

A flaw was found in GNU tar. When extracting an archive with the --one-top-level option, hardlink targets are not confined to the designated top-level directory and may resolve relative to the extraction working directory. A crafted archive can create hardlinks that escape the intended boundary and, when combined with a preexisting symbolic link under the working directory, may allow writing outside that boundary during a single extraction.

### CVE-2026-42250

- **Package:** `libbz2-1.0`
- **Installed:** `1.0.8-5+b1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-42250](https://security-tracker.debian.org/tracker/CVE-2026-42250)

bzip2 contains an off‑by‑one error in the bzip2recover utility. When processing a specially crafted file, the application performs an out‑of‑bounds write to a global buffer, resulting in memory corruption and a crash (denial of service).  This issue was fixed in bzip2 patch 35d122a3df8b0cc4082a4d89fdc6ee99f375fe67

### CVE-2026-18938

- **Package:** `libp11-kit0`
- **Installed:** `0.24.1-2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-18938](https://security-tracker.debian.org/tracker/CVE-2026-18938)

A flaw was found in p11-kit. A local attacker, or one with equivalent access to a reachable RPC channel, could exploit an integer overflow vulnerability. By sending specially crafted messages, the attacker can cause the system to miscalculate memory allocation for nested attributes. This leads to a memory corruption issue, specifically a heap out-of-bounds write, which can crash the p11-kit RPC parsing process, resulting in a Denial of Service (DoS). This vulnerability is only exploitable on 32 bit systems.

### CVE-2026-106586

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-106586](https://security-tracker.debian.org/tracker/CVE-2026-106586)

In sshd in OpenSSH before 10.6, the restrict keyword (in authorized_keys) was supposed to be applicable to tunnel forwarding but was not, a different vulnerability than CVE-2026-73283.

### CVE-2026-41991

- **Package:** `gzip`
- **Installed:** `1.12-1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-41991](https://security-tracker.debian.org/tracker/CVE-2026-41991)

GNU gzip contains a vulnerability in the gzexe utility related to insecure temporary file handling. When the mktemp utility is not available in the user’s PATH, gzexe falls back to constructing a temporary file path based solely on the process ID (PID). This predictable filename is created without exclusive access or existence checks. A local attacker can pre‑create the predicted temporary file path as a symbolic link pointing to an arbitrary file writable by the victim. When gzexe runs, it follows the symlink and overwrites the target file, resulting in a time‑of‑check to time‑of‑use (TOCTOU) condition that allows arbitrary file overwrite.  This issue has been fixed in the commit 4e6f8b24ab823146ab8776f0b7fe486ab34d4269

### CVE-2026-86805

- **Package:** `libc-bin`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-86805](https://security-tracker.debian.org/tracker/CVE-2026-86805)

A time-of-check to time-of-use (TOCTOU) race condition in the dynamic loader (ld.so) of the GNU C Library (glibc) versions 2.14 through 2.44 allows a local attacker to escalate privileges. When expanding $ORIGIN in DT_RPATH for setuid/setgid (AT_SECURE) programs, glibc validates the lexically normalized search path against the trusted directories but then opens the raw, un-normalized path. On systems where the Linux fs.protected_hardlinks sysctl is disabled, a local attacker who hard-links such a program into an attacker-controlled directory and wins a race to replace an intermediate path component with a symbolic link can direct the loader outside the trusted directory, causing it to load an attacker-controlled shared object and execute arbitrary code with the elevated privileges of the program.  Exploitation requires an installed setuid or setgid binary whose DT_RPATH uses $ORIGIN followed by ".." traversal that normalizes into a trusted directory, and the ability to hard-link that binary and win the race by swapping a path component for a symbolic link. Major Linux-based OS distributions ship with fs.protected_hardlinks enabled by default and mitigate the vulnerability.

### CVE-2026-86805

- **Package:** `libc6`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-86805](https://security-tracker.debian.org/tracker/CVE-2026-86805)

A time-of-check to time-of-use (TOCTOU) race condition in the dynamic loader (ld.so) of the GNU C Library (glibc) versions 2.14 through 2.44 allows a local attacker to escalate privileges. When expanding $ORIGIN in DT_RPATH for setuid/setgid (AT_SECURE) programs, glibc validates the lexically normalized search path against the trusted directories but then opens the raw, un-normalized path. On systems where the Linux fs.protected_hardlinks sysctl is disabled, a local attacker who hard-links such a program into an attacker-controlled directory and wins a race to replace an intermediate path component with a symbolic link can direct the loader outside the trusted directory, causing it to load an attacker-controlled shared object and execute arbitrary code with the elevated privileges of the program.  Exploitation requires an installed setuid or setgid binary whose DT_RPATH uses $ORIGIN followed by ".." traversal that normalizes into a trusted directory, and the ability to hard-link that binary and win the race by swapping a path component for a symbolic link. Major Linux-based OS distributions ship with fs.protected_hardlinks enabled by default and mitigate the vulnerability.

### CVE-2025-68972

- **Package:** `gpgv`
- **Installed:** `2.2.40-1.1+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-68972](https://security-tracker.debian.org/tracker/CVE-2025-68972)

In GnuPG through 2.4.8, if a signed message has \f at the end of a plaintext line, an adversary can construct a modified message that places additional text after the signed material, such that signature verification of the modified message succeeds (although an "invalid armor" message is printed during verification). This is related to use of \f as a marker to denote truncation of a long plaintext line.

### CVE-2026-18477

- **Package:** `tar`
- **Installed:** `1.34+dfsg-1.2+deb12u1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-18477](https://security-tracker.debian.org/tracker/CVE-2026-18477)

A TOCTOU (Time-of-Check Time-of-Use) vulnerability in GNU tar's incremental dumpdir 'X' rename handling allows a local attacker with write access to a directory being backed up to influence the restore process if the attacker has access to the system where the restore is being performed. During restoration, files or directories may be created, renamed or overwritten outside the intended extraction directory. This could lead to unauthorized file modification or, in some cases, privilege escalation. Exploitation does not require the attacker to modify or craft the archive, and standard backup and restore workflows—including extracting into a newly created directory without using the -P option do not mitigate the issue.

### CVE-2026-16742

- **Package:** `libsystemd0`
- **Installed:** `252.39-1~deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-16742](https://security-tracker.debian.org/tracker/CVE-2026-16742)

systemd-homed contains a local privilege escalation bug via arbitrary system group addition to a local, logged in, homed-managed user

### CVE-2026-16742

- **Package:** `libudev1`
- **Installed:** `252.39-1~deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-16742](https://security-tracker.debian.org/tracker/CVE-2026-16742)

systemd-homed contains a local privilege escalation bug via arbitrary system group addition to a local, logged in, homed-managed user

## Low (18)

### CVE-2024-56433

- **Package:** `login`
- **Installed:** `1:4.13+dfsg1-1+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2024-56433](https://security-tracker.debian.org/tracker/CVE-2024-56433)

shadow-utils (aka shadow) 4.4 through 4.17.0 establishes a default /etc/subuid behavior (e.g., uid 100000 through 165535 for the first user account) that can realistically conflict with the uids of users defined on locally administered networks, potentially leading to account takeover, e.g., by leveraging newuidmap for access to an NFS home directory (or same-host resources in the case of remote logins by these local network users). NOTE: it may also be argued that system administrators should not have assigned uids, within local networks, that are within the range that can occur in /etc/subuid.

### CVE-2024-56433

- **Package:** `passwd`
- **Installed:** `1:4.13+dfsg1-1+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2024-56433](https://security-tracker.debian.org/tracker/CVE-2024-56433)

shadow-utils (aka shadow) 4.4 through 4.17.0 establishes a default /etc/subuid behavior (e.g., uid 100000 through 165535 for the first user account) that can realistically conflict with the uids of users defined on locally administered networks, potentially leading to account takeover, e.g., by leveraging newuidmap for access to an NFS home directory (or same-host resources in the case of remote logins by these local network users). NOTE: it may also be argued that system administrators should not have assigned uids, within local networks, that are within the range that can occur in /etc/subuid.

### CVE-2016-2781

- **Package:** `coreutils`
- **Installed:** `9.1-1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2016-2781](https://security-tracker.debian.org/tracker/CVE-2016-2781)

chroot in GNU coreutils, when used with --userspec, allows local users to escape to the parent session via a crafted TIOCSTI ioctl call, which pushes characters to the terminal's input buffer.

### CVE-2026-97399

- **Package:** `libc-bin`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-97399](https://security-tracker.debian.org/tracker/CVE-2026-97399)

The strncasecmp function in the GNU C Library 2.24 and later optimized for the Power8 architecture may read one byte beyond the input size limit, which may crash a program when that byte is not readable.  This condition may happen when the input strings to the strncasecmp function are attacker controlled in an application and they match all the way up to the edge of their page and the neighbouring page is either not mapped or is not readable.

### CVE-2026-97399

- **Package:** `libc6`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-97399](https://security-tracker.debian.org/tracker/CVE-2026-97399)

The strncasecmp function in the GNU C Library 2.24 and later optimized for the Power8 architecture may read one byte beyond the input size limit, which may crash a program when that byte is not readable.  This condition may happen when the input strings to the strncasecmp function are attacker controlled in an application and they match all the way up to the edge of their page and the neighbouring page is either not mapped or is not readable.

### CVE-2026-103995

- **Package:** `python`
- **Installed:** `3.13.18`
- **Fixed in:** `3.16.0`
- **Reference:** [CVE-2026-103995](https://nvd.nist.gov/vuln/detail/CVE-2026-103995)

Response body and chunk parsing would handle non-hex or negative integers incorrectly which could result in misinterpreting HTTP response contents.

### CVE-2026-106582

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-106582](https://security-tracker.debian.org/tracker/CVE-2026-106582)

In sshd and ssh in OpenSSH before 10.6, an LZ77 dictionary coder can be used even though this is contraindicated by the arXiv 2609.07709 "Crossing the Streams" findings.

### CVE-2026-40228

- **Package:** `libsystemd0`
- **Installed:** `252.39-1~deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-40228](https://security-tracker.debian.org/tracker/CVE-2026-40228)

In systemd 259, systemd-journald can send ANSI escape sequences to the terminals of arbitrary users when a "logger -p emerg" command is executed, if ForwardToWall=yes is set.

### CVE-2026-40228

- **Package:** `libudev1`
- **Installed:** `252.39-1~deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-40228](https://security-tracker.debian.org/tracker/CVE-2026-40228)

In systemd 259, systemd-journald can send ANSI escape sequences to the terminals of arbitrary users when a "logger -p emerg" command is executed, if ForwardToWall=yes is set.

### CVE-2026-73281

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-73281](https://security-tracker.debian.org/tracker/CVE-2026-73281)

In ssh-agent in OpenSSH before 10.5, some operations can occur remotely but were intended to occur only locally, including operations that add tokens or use keys. This is caused by misinteraction between agent locking and the session-bind@openssh.com extension.

### CVE-2026-57062

- **Package:** `gpgv`
- **Installed:** `2.2.40-1.1+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-57062](https://security-tracker.debian.org/tracker/CVE-2026-57062)

CMS (Cryptographic Message Syntax) parsing in gpgsm in GnuPG through 2.5.20 mishandles the CMS format for AES-GCM because aes-ICVlen is supposed to be 12 bytes but 4 bytes is accepted. NOTE: this is related to CVE-2026-34182.

### CVE-2026-95818

- **Package:** `libc-bin`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-95818](https://security-tracker.debian.org/tracker/CVE-2026-95818)

A stack-based buffer overflow in the dynamic loader (ld.so) of the GNU C Library (glibc) versions 2.14 through 2.44 allows a local attacker to crash or corrupt the memory of setuid/setgid (AT_SECURE) programs.  When such a program's DT_RPATH or DT_RUNPATH begins with $ORIGIN and is followed by NUL or '/' the loader both reads past the end of the path buffer and writes past the end of a stack-allocated internal buffer. The corrupted loader stack can lead to a loader crash (denial of service) and limited disclosure of process memory.

### CVE-2026-95818

- **Package:** `libc6`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-95818](https://security-tracker.debian.org/tracker/CVE-2026-95818)

A stack-based buffer overflow in the dynamic loader (ld.so) of the GNU C Library (glibc) versions 2.14 through 2.44 allows a local attacker to crash or corrupt the memory of setuid/setgid (AT_SECURE) programs.  When such a program's DT_RPATH or DT_RUNPATH begins with $ORIGIN and is followed by NUL or '/' the loader both reads past the end of the path buffer and writes past the end of a stack-allocated internal buffer. The corrupted loader stack can lead to a loader crash (denial of service) and limited disclosure of process memory.

### CVE-2026-105712

- **Package:** `gpgv`
- **Installed:** `2.2.40-1.1+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-105712](https://security-tracker.debian.org/tracker/CVE-2026-105712)

gpgtar in GnuPG before 2.5.19 can allow file overwrite via crafted data in an archive. When extracting an untrusted archive with --directory (aka -C) into an existing directory containing a pre-existing symlink, gpgtar can follow that symlink and create or overwrite a file outside the selected extraction directory. The write is limited by the extraction user's filesystem permissions. An archive extracted into a fresh empty directory does not have this risk.

### CVE-2026-73283

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-73283](https://security-tracker.debian.org/tracker/CVE-2026-73283)

In sshd in OpenSSH before 10.5, the restrict keyword (in authorized_keys) was supposed to be applicable to tunnel forwarding but was not.

### CVE-2026-6368

- **Package:** `libc-bin`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-6368](https://security-tracker.debian.org/tracker/CVE-2026-6368)

Calling wordexp with WRDE_APPEND in the GNU C Library version 2.0 to version 2.43 can cause the interface to return invalid memory in the we_wordv member, which on subsequent calls to wordfree may abort the process.

### CVE-2026-6368

- **Package:** `libc6`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-6368](https://security-tracker.debian.org/tracker/CVE-2026-6368)

Calling wordexp with WRDE_APPEND in the GNU C Library version 2.0 to version 2.43 can cause the interface to return invalid memory in the we_wordv member, which on subsequent calls to wordfree may abort the process.

### CVE-2026-106587

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-106587](https://security-tracker.debian.org/tracker/CVE-2026-106587)

In sshd in OpenSSH before 10.6, the value "none" for a configuration option is sometimes interpreted as a filename but was intended to mean that a feature is disabled.

## Negligible (98)

### CVE-2011-3389

- **Package:** `libgnutls30`
- **Installed:** `3.7.9-2+deb12u7`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2011-3389](https://security-tracker.debian.org/tracker/CVE-2011-3389)

The SSL protocol, as used in certain configurations in Microsoft Windows and Microsoft Internet Explorer, Mozilla Firefox, Google Chrome, Opera, and other products, encrypts data by using CBC mode with chained initialization vectors, which allows man-in-the-middle attackers to obtain plaintext HTTP headers via a blockwise chosen-boundary attack (BCBA) on an HTTPS session, in conjunction with JavaScript code that uses (1) the HTML5 WebSocket API, (2) the Java URLConnection API, or (3) the Silverlight WebClient API, aka a "BEAST" attack.

### CVE-2019-6110

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2019-6110](https://security-tracker.debian.org/tracker/CVE-2019-6110)

In OpenSSH 7.9, due to accepting and displaying arbitrary stderr output from the server, a malicious server (or Man-in-The-Middle attacker) can manipulate the client output, for example to use ANSI control codes to hide additional files being transferred.

### CVE-2020-15778

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2020-15778](https://security-tracker.debian.org/tracker/CVE-2020-15778)

scp in OpenSSH through 8.3p1 allows command injection in the scp.c toremote function, as demonstrated by backtick characters in the destination argument. NOTE: the vendor reportedly has stated that they intentionally omit validation of "anomalous argument transfers" because that could "stand a great chance of breaking existing workflows."

### CVE-2007-2768

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2007-2768](https://security-tracker.debian.org/tracker/CVE-2007-2768)

OpenSSH, when using OPIE (One-Time Passwords in Everything) for PAM, allows remote attackers to determine the existence of certain user accounts, which displays a different response if the user account exists and is configured to use one-time passwords (OTP), a similar issue to CVE-2007-2243.

### CVE-2018-20796

- **Package:** `libc-bin`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2018-20796](https://security-tracker.debian.org/tracker/CVE-2018-20796)

In the GNU C Library (aka glibc or libc6) through 2.29, check_dst_limits_calc_pos_1 in posix/regexec.c has Uncontrolled Recursion, as demonstrated by '(\227|)(\\1\\1|t1|\\\2537)+' in grep.

### CVE-2018-20796

- **Package:** `libc6`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2018-20796](https://security-tracker.debian.org/tracker/CVE-2018-20796)

In the GNU C Library (aka glibc or libc6) through 2.29, check_dst_limits_calc_pos_1 in posix/regexec.c has Uncontrolled Recursion, as demonstrated by '(\227|)(\\1\\1|t1|\\\2537)+' in grep.

### CVE-2008-3234

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2008-3234](https://security-tracker.debian.org/tracker/CVE-2008-3234)

sshd in OpenSSH 4 on Debian GNU/Linux, and the 20070303 OpenSSH snapshot, allows remote authenticated users to obtain access to arbitrary SELinux roles by appending a :/ (colon slash) sequence, followed by the role name, to the username.

### CVE-2016-20012

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2016-20012](https://security-tracker.debian.org/tracker/CVE-2016-20012)

OpenSSH through 8.7 allows remote attackers, who have a suspicion that a certain combination of username and public key is known to an SSH server, to test whether this suspicion is correct. This occurs because a challenge is sent only when that combination could be valid for a login session. NOTE: the vendor does not recognize user enumeration as a vulnerability for this product

### CVE-2005-2541

- **Package:** `tar`
- **Installed:** `1.34+dfsg-1.2+deb12u1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2005-2541](https://security-tracker.debian.org/tracker/CVE-2005-2541)

Tar 1.15.1 does not properly warn the user when extracting setuid or setgid files, which may allow local users or remote attackers to gain privileges.

### CVE-2018-15919

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2018-15919](https://security-tracker.debian.org/tracker/CVE-2018-15919)

Remotely observable behaviour in auth-gss2.c in OpenSSH through 7.8 could be used by remote attackers to detect existence of users on a target system when GSS2 is in use. NOTE: the discoverer states 'We understand that the OpenSSH developers do not want to treat such a username enumeration (or "oracle") as a vulnerability.'

### CVE-2019-1010022

- **Package:** `libc-bin`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2019-1010022](https://security-tracker.debian.org/tracker/CVE-2019-1010022)

GNU Libc current is affected by: Mitigation bypass. The impact is: Attacker may bypass stack guard protection. The component is: nptl. The attack vector is: Exploit stack buffer overflow vulnerability and use this bypass vulnerability to bypass stack guard. NOTE: Upstream comments indicate "this is being treated as a non-security bug and no real threat.

### CVE-2019-1010022

- **Package:** `libc6`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2019-1010022](https://security-tracker.debian.org/tracker/CVE-2019-1010022)

GNU Libc current is affected by: Mitigation bypass. The impact is: Attacker may bypass stack guard protection. The component is: nptl. The attack vector is: Exploit stack buffer overflow vulnerability and use this bypass vulnerability to bypass stack guard. NOTE: Upstream comments indicate "this is being treated as a non-security bug and no real threat.

### CVE-2019-1010024

- **Package:** `libc-bin`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2019-1010024](https://security-tracker.debian.org/tracker/CVE-2019-1010024)

GNU Libc current is affected by: Mitigation bypass. The impact is: Attacker may bypass ASLR using cache of thread stack and heap. The component is: glibc. NOTE: Upstream comments indicate "this is being treated as a non-security bug and no real threat.

### CVE-2019-1010024

- **Package:** `libc6`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2019-1010024](https://security-tracker.debian.org/tracker/CVE-2019-1010024)

GNU Libc current is affected by: Mitigation bypass. The impact is: Attacker may bypass ASLR using cache of thread stack and heap. The component is: glibc. NOTE: Upstream comments indicate "this is being treated as a non-security bug and no real threat.

### CVE-2019-1010023

- **Package:** `libc-bin`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2019-1010023](https://security-tracker.debian.org/tracker/CVE-2019-1010023)

GNU Libc current is affected by: Re-mapping current loaded library with malicious ELF file. The impact is: In worst case attacker may evaluate privileges. The component is: libld. The attack vector is: Attacker sends 2 ELF files to victim and asks to run ldd on it. ldd execute code. NOTE: Upstream comments indicate "this is being treated as a non-security bug and no real threat.

### CVE-2019-1010023

- **Package:** `libc6`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2019-1010023](https://security-tracker.debian.org/tracker/CVE-2019-1010023)

GNU Libc current is affected by: Re-mapping current loaded library with malicious ELF file. The impact is: In worst case attacker may evaluate privileges. The component is: libld. The attack vector is: Attacker sends 2 ELF files to victim and asks to run ldd on it. ldd execute code. NOTE: Upstream comments indicate "this is being treated as a non-security bug and no real threat.

### CVE-2020-14145

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2020-14145](https://security-tracker.debian.org/tracker/CVE-2020-14145)

The client side in OpenSSH 5.7 through 8.4 has an Observable Discrepancy leading to an information leak in the algorithm negotiation. This allows man-in-the-middle attackers to target initial connection attempts (where no host key for the server has been cached by the client). NOTE: some reports state that 8.5 and 8.6 are also affected.

### CVE-2010-4756

- **Package:** `libc-bin`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2010-4756](https://security-tracker.debian.org/tracker/CVE-2010-4756)

The glob implementation in the GNU C Library (aka glibc or libc6) allows remote authenticated users to cause a denial of service (CPU and memory consumption) via crafted glob expressions that do not match any pathnames, as demonstrated by glob expressions in STAT commands to an FTP daemon, a different vulnerability than CVE-2010-2632.

### CVE-2010-4756

- **Package:** `libc6`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2010-4756](https://security-tracker.debian.org/tracker/CVE-2010-4756)

The glob implementation in the GNU C Library (aka glibc or libc6) allows remote authenticated users to cause a denial of service (CPU and memory consumption) via crafted glob expressions that do not match any pathnames, as demonstrated by glob expressions in STAT commands to an FTP daemon, a different vulnerability than CVE-2010-2632.

### CVE-2019-1010025

- **Package:** `libc-bin`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2019-1010025](https://security-tracker.debian.org/tracker/CVE-2019-1010025)

GNU Libc current is affected by: Mitigation bypass. The impact is: Attacker may guess the heap addresses of pthread_created thread. The component is: glibc. NOTE: the vendor's position is "ASLR bypass itself is not a vulnerability.

### CVE-2019-1010025

- **Package:** `libc6`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2019-1010025](https://security-tracker.debian.org/tracker/CVE-2019-1010025)

GNU Libc current is affected by: Mitigation bypass. The impact is: Attacker may guess the heap addresses of pthread_created thread. The component is: glibc. NOTE: the vendor's position is "ASLR bypass itself is not a vulnerability.

### CVE-2019-9192

- **Package:** `libc-bin`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2019-9192](https://security-tracker.debian.org/tracker/CVE-2019-9192)

In the GNU C Library (aka glibc or libc6) through 2.29, check_dst_limits_calc_pos_1 in posix/regexec.c has Uncontrolled Recursion, as demonstrated by '(|)(\\1\\1)*' in grep, a different issue than CVE-2018-20796. NOTE: the software maintainer disputes that this is a vulnerability because the behavior occurs only with a crafted pattern

### CVE-2019-9192

- **Package:** `libc6`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2019-9192](https://security-tracker.debian.org/tracker/CVE-2019-9192)

In the GNU C Library (aka glibc or libc6) through 2.29, check_dst_limits_calc_pos_1 in posix/regexec.c has Uncontrolled Recursion, as demonstrated by '(|)(\\1\\1)*' in grep, a different issue than CVE-2018-20796. NOTE: the software maintainer disputes that this is a vulnerability because the behavior occurs only with a crafted pattern

### CVE-2007-2243

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2007-2243](https://security-tracker.debian.org/tracker/CVE-2007-2243)

OpenSSH 4.6 and earlier, when ChallengeResponseAuthentication is enabled, allows remote attackers to determine the existence of user accounts by attempting to authenticate via S/KEY, which displays a different response if the user account exists, a similar issue to CVE-2001-1483.

### CVE-2018-5709

- **Package:** `libgssapi-krb5-2`
- **Installed:** `1.20.1-2+deb12u5`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2018-5709](https://security-tracker.debian.org/tracker/CVE-2018-5709)

An issue was discovered in MIT Kerberos 5 (aka krb5) through 1.16. There is a variable "dbentry->n_key_data" in kadmin/dbutil/dump.c that can store 16-bit data but unknowingly the developer has assigned a "u4" variable to it, which is for 32-bit data. An attacker can use this vulnerability to affect other artifacts of the database as we know that a Kerberos database dump file contains trusted data.

### CVE-2018-5709

- **Package:** `libk5crypto3`
- **Installed:** `1.20.1-2+deb12u5`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2018-5709](https://security-tracker.debian.org/tracker/CVE-2018-5709)

An issue was discovered in MIT Kerberos 5 (aka krb5) through 1.16. There is a variable "dbentry->n_key_data" in kadmin/dbutil/dump.c that can store 16-bit data but unknowingly the developer has assigned a "u4" variable to it, which is for 32-bit data. An attacker can use this vulnerability to affect other artifacts of the database as we know that a Kerberos database dump file contains trusted data.

### CVE-2018-5709

- **Package:** `libkrb5-3`
- **Installed:** `1.20.1-2+deb12u5`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2018-5709](https://security-tracker.debian.org/tracker/CVE-2018-5709)

An issue was discovered in MIT Kerberos 5 (aka krb5) through 1.16. There is a variable "dbentry->n_key_data" in kadmin/dbutil/dump.c that can store 16-bit data but unknowingly the developer has assigned a "u4" variable to it, which is for 32-bit data. An attacker can use this vulnerability to affect other artifacts of the database as we know that a Kerberos database dump file contains trusted data.

### CVE-2018-5709

- **Package:** `libkrb5support0`
- **Installed:** `1.20.1-2+deb12u5`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2018-5709](https://security-tracker.debian.org/tracker/CVE-2018-5709)

An issue was discovered in MIT Kerberos 5 (aka krb5) through 1.16. There is a variable "dbentry->n_key_data" in kadmin/dbutil/dump.c that can store 16-bit data but unknowingly the developer has assigned a "u4" variable to it, which is for 32-bit data. An attacker can use this vulnerability to affect other artifacts of the database as we know that a Kerberos database dump file contains trusted data.

### CVE-2018-6829

- **Package:** `libgcrypt20`
- **Installed:** `1.10.1-3+deb12u1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2018-6829](https://security-tracker.debian.org/tracker/CVE-2018-6829)

cipher/elgamal.c in Libgcrypt through 1.8.2, when used to encrypt messages directly, improperly encodes plaintexts, which allows attackers to obtain sensitive information by reading ciphertext data (i.e., it does not have semantic security in face of a ciphertext-only attack). The Decisional Diffie-Hellman (DDH) assumption does not hold for Libgcrypt's ElGamal implementation.

### CVE-2023-31486

- **Package:** `perl-base`
- **Installed:** `5.36.0-7+deb12u4`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2023-31486](https://security-tracker.debian.org/tracker/CVE-2023-31486)

HTTP::Tiny before 0.083, a Perl core module since 5.13.9 and available standalone on CPAN, has an insecure default TLS configuration where users must opt in to verify certificates.

### CVE-2021-45346

- **Package:** `libsqlite3-0`
- **Installed:** `3.40.1-2+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2021-45346](https://security-tracker.debian.org/tracker/CVE-2021-45346)

A Memory Leak vulnerability exists in SQLite Project SQLite3 3.35.1 and 3.37.0 via maliciously crafted SQL Queries (made via editing the Database File), it is possible to query a record, and leak subsequent bytes of memory that extend beyond the record, which could let a malicious user obtain sensitive information. NOTE: The developer disputes this as a vulnerability stating that If you give SQLite a corrupted database file and submit a query against the database, it might read parts of the database that you did not intend or expect.

### CVE-2021-45346

- **Package:** `sqlite3`
- **Installed:** `3.40.1-2+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2021-45346](https://security-tracker.debian.org/tracker/CVE-2021-45346)

A Memory Leak vulnerability exists in SQLite Project SQLite3 3.35.1 and 3.37.0 via maliciously crafted SQL Queries (made via editing the Database File), it is possible to query a record, and leak subsequent bytes of memory that extend beyond the record, which could let a malicious user obtain sensitive information. NOTE: The developer disputes this as a vulnerability stating that If you give SQLite a corrupted database file and submit a query against the database, it might read parts of the database that you did not intend or expect.

### CVE-2011-3374

- **Package:** `apt`
- **Installed:** `2.6.1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2011-3374](https://security-tracker.debian.org/tracker/CVE-2011-3374)

It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyring, leading to a potential man-in-the-middle attack.

### CVE-2011-3374

- **Package:** `libapt-pkg6.0`
- **Installed:** `2.6.1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2011-3374](https://security-tracker.debian.org/tracker/CVE-2011-3374)

It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyring, leading to a potential man-in-the-middle attack.

### CVE-2024-2236

- **Package:** `libgcrypt20`
- **Installed:** `1.10.1-3+deb12u1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2024-2236](https://security-tracker.debian.org/tracker/CVE-2024-2236)

A timing-based side-channel flaw was found in libgcrypt's RSA implementation. This issue may allow a remote attacker to initiate a Bleichenbacher-style attack, which can lead to the decryption of RSA ciphertexts.

### CVE-2024-26461

- **Package:** `libgssapi-krb5-2`
- **Installed:** `1.20.1-2+deb12u5`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2024-26461](https://security-tracker.debian.org/tracker/CVE-2024-26461)

Kerberos 5 (aka krb5) 1.21.2 contains a memory leak vulnerability in /krb5/src/lib/gssapi/krb5/k5sealv3.c.

### CVE-2024-26461

- **Package:** `libk5crypto3`
- **Installed:** `1.20.1-2+deb12u5`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2024-26461](https://security-tracker.debian.org/tracker/CVE-2024-26461)

Kerberos 5 (aka krb5) 1.21.2 contains a memory leak vulnerability in /krb5/src/lib/gssapi/krb5/k5sealv3.c.

### CVE-2024-26461

- **Package:** `libkrb5-3`
- **Installed:** `1.20.1-2+deb12u5`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2024-26461](https://security-tracker.debian.org/tracker/CVE-2024-26461)

Kerberos 5 (aka krb5) 1.21.2 contains a memory leak vulnerability in /krb5/src/lib/gssapi/krb5/k5sealv3.c.

### CVE-2024-26461

- **Package:** `libkrb5support0`
- **Installed:** `1.20.1-2+deb12u5`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2024-26461](https://security-tracker.debian.org/tracker/CVE-2024-26461)

Kerberos 5 (aka krb5) 1.21.2 contains a memory leak vulnerability in /krb5/src/lib/gssapi/krb5/k5sealv3.c.

### CVE-2022-27943

- **Package:** `gcc-12-base`
- **Installed:** `12.2.0-14+deb12u1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2022-27943](https://security-tracker.debian.org/tracker/CVE-2022-27943)

libiberty/rust-demangle.c in GNU GCC 11.2 allows stack consumption in demangle_const, as demonstrated by nm-new.

### CVE-2022-27943

- **Package:** `libgcc-s1`
- **Installed:** `12.2.0-14+deb12u1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2022-27943](https://security-tracker.debian.org/tracker/CVE-2022-27943)

libiberty/rust-demangle.c in GNU GCC 11.2 allows stack consumption in demangle_const, as demonstrated by nm-new.

### CVE-2022-27943

- **Package:** `libstdc++6`
- **Installed:** `12.2.0-14+deb12u1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2022-27943](https://security-tracker.debian.org/tracker/CVE-2022-27943)

libiberty/rust-demangle.c in GNU GCC 11.2 allows stack consumption in demangle_const, as demonstrated by nm-new.

### CVE-2007-5686

- **Package:** `login`
- **Installed:** `1:4.13+dfsg1-1+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2007-5686](https://security-tracker.debian.org/tracker/CVE-2007-5686)

initscripts in rPath Linux 1 sets insecure permissions for the /var/log/btmp file, which allows local users to obtain sensitive information regarding authentication attempts.  NOTE: because sshd detects the insecure permissions and does not log certain events, this also prevents sshd from logging failed authentication attempts by remote attackers.

### CVE-2007-5686

- **Package:** `passwd`
- **Installed:** `1:4.13+dfsg1-1+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2007-5686](https://security-tracker.debian.org/tracker/CVE-2007-5686)

initscripts in rPath Linux 1 sets insecure permissions for the /var/log/btmp file, which allows local users to obtain sensitive information regarding authentication attempts.  NOTE: because sshd detects the insecure permissions and does not log certain events, this also prevents sshd from logging failed authentication attempts by remote attackers.

### CVE-2024-26458

- **Package:** `libgssapi-krb5-2`
- **Installed:** `1.20.1-2+deb12u5`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2024-26458](https://security-tracker.debian.org/tracker/CVE-2024-26458)

Kerberos 5 (aka krb5) 1.21.2 contains a memory leak in /krb5/src/lib/rpc/pmap_rmt.c.

### CVE-2024-26458

- **Package:** `libk5crypto3`
- **Installed:** `1.20.1-2+deb12u5`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2024-26458](https://security-tracker.debian.org/tracker/CVE-2024-26458)

Kerberos 5 (aka krb5) 1.21.2 contains a memory leak in /krb5/src/lib/rpc/pmap_rmt.c.

### CVE-2024-26458

- **Package:** `libkrb5-3`
- **Installed:** `1.20.1-2+deb12u5`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2024-26458](https://security-tracker.debian.org/tracker/CVE-2024-26458)

Kerberos 5 (aka krb5) 1.21.2 contains a memory leak in /krb5/src/lib/rpc/pmap_rmt.c.

### CVE-2024-26458

- **Package:** `libkrb5support0`
- **Installed:** `1.20.1-2+deb12u5`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2024-26458](https://security-tracker.debian.org/tracker/CVE-2024-26458)

Kerberos 5 (aka krb5) 1.21.2 contains a memory leak in /krb5/src/lib/rpc/pmap_rmt.c.

### CVE-2011-4116

- **Package:** `perl-base`
- **Installed:** `5.36.0-7+deb12u4`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2011-4116](https://security-tracker.debian.org/tracker/CVE-2011-4116)

_is_safe in the File::Temp module for Perl does not properly handle symlinks.

### CVE-2013-4392

- **Package:** `libsystemd0`
- **Installed:** `252.39-1~deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2013-4392](https://security-tracker.debian.org/tracker/CVE-2013-4392)

systemd, when updating file permissions, allows local users to change the permissions and SELinux security contexts for arbitrary files via a symlink attack on unspecified files.

### CVE-2013-4392

- **Package:** `libudev1`
- **Installed:** `252.39-1~deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2013-4392](https://security-tracker.debian.org/tracker/CVE-2013-4392)

systemd, when updating file permissions, allows local users to change the permissions and SELinux security contexts for arbitrary files via a symlink attack on unspecified files.

### CVE-2025-70873

- **Package:** `libsqlite3-0`
- **Installed:** `3.40.1-2+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-70873](https://security-tracker.debian.org/tracker/CVE-2025-70873)

An information disclosure issue in the zipfileInflate function in the zipfile extension in SQLite v3.51.1 and earlier allows attackers to obtain heap memory via supplying a crafted ZIP file.

### CVE-2025-70873

- **Package:** `sqlite3`
- **Installed:** `3.40.1-2+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-70873](https://security-tracker.debian.org/tracker/CVE-2025-70873)

An information disclosure issue in the zipfileInflate function in the zipfile extension in SQLite v3.51.1 and earlier allows attackers to obtain heap memory via supplying a crafted ZIP file.

### CVE-2025-27587

- **Package:** `libssl3`
- **Installed:** `3.0.22-1~deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-27587](https://security-tracker.debian.org/tracker/CVE-2025-27587)

OpenSSL 3.0.0 through 3.3.2 on the PowerPC architecture is vulnerable to a Minerva attack, exploitable by measuring the time of signing of random messages using the EVP_DigestSign API, and then using the private key to extract the K value (nonce) from the signatures. Next, based on the bit size of the extracted nonce, one can compare the signing time of full-sized nonces to signatures that used smaller nonces, via statistical tests. There is a side-channel in the P-364 curve that allows private key extraction (also, there is a dependency between the bit size of K and the size of the side channel). NOTE: This CVE is disputed because the OpenSSL security policy explicitly notes that any side channels which require same physical system to be detected are outside of the threat model for the software. The timing signal is so small that it is infeasible to be detected without having the attacking process running on the same physical system.

### CVE-2025-27587

- **Package:** `openssl`
- **Installed:** `3.0.22-1~deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-27587](https://security-tracker.debian.org/tracker/CVE-2025-27587)

OpenSSL 3.0.0 through 3.3.2 on the PowerPC architecture is vulnerable to a Minerva attack, exploitable by measuring the time of signing of random messages using the EVP_DigestSign API, and then using the private key to extract the K value (nonce) from the signatures. Next, based on the bit size of the extracted nonce, one can compare the signing time of full-sized nonces to signatures that used smaller nonces, via statistical tests. There is a side-channel in the P-364 curve that allows private key extraction (also, there is a dependency between the bit size of K and the size of the side channel). NOTE: This CVE is disputed because the OpenSSL security policy explicitly notes that any side channels which require same physical system to be detected are outside of the threat model for the software. The timing signal is so small that it is infeasible to be detected without having the attacking process running on the same physical system.

### CVE-2022-0563

- **Package:** `bsdutils`
- **Installed:** `1:2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2022-0563](https://security-tracker.debian.org/tracker/CVE-2022-0563)

A flaw was found in the util-linux chfn and chsh utilities when compiled with Readline support. The Readline library uses an "INPUTRC" environment variable to get a path to the library config file. When the library cannot parse the specified file, it prints an error message containing data from the file. This flaw allows an unprivileged user to read root-owned files, potentially leading to privilege escalation. This flaw affects util-linux versions prior to 2.37.4.

### CVE-2022-0563

- **Package:** `libblkid1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2022-0563](https://security-tracker.debian.org/tracker/CVE-2022-0563)

A flaw was found in the util-linux chfn and chsh utilities when compiled with Readline support. The Readline library uses an "INPUTRC" environment variable to get a path to the library config file. When the library cannot parse the specified file, it prints an error message containing data from the file. This flaw allows an unprivileged user to read root-owned files, potentially leading to privilege escalation. This flaw affects util-linux versions prior to 2.37.4.

### CVE-2022-0563

- **Package:** `libmount1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2022-0563](https://security-tracker.debian.org/tracker/CVE-2022-0563)

A flaw was found in the util-linux chfn and chsh utilities when compiled with Readline support. The Readline library uses an "INPUTRC" environment variable to get a path to the library config file. When the library cannot parse the specified file, it prints an error message containing data from the file. This flaw allows an unprivileged user to read root-owned files, potentially leading to privilege escalation. This flaw affects util-linux versions prior to 2.37.4.

### CVE-2022-0563

- **Package:** `libsmartcols1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2022-0563](https://security-tracker.debian.org/tracker/CVE-2022-0563)

A flaw was found in the util-linux chfn and chsh utilities when compiled with Readline support. The Readline library uses an "INPUTRC" environment variable to get a path to the library config file. When the library cannot parse the specified file, it prints an error message containing data from the file. This flaw allows an unprivileged user to read root-owned files, potentially leading to privilege escalation. This flaw affects util-linux versions prior to 2.37.4.

### CVE-2022-0563

- **Package:** `libuuid1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2022-0563](https://security-tracker.debian.org/tracker/CVE-2022-0563)

A flaw was found in the util-linux chfn and chsh utilities when compiled with Readline support. The Readline library uses an "INPUTRC" environment variable to get a path to the library config file. When the library cannot parse the specified file, it prints an error message containing data from the file. This flaw allows an unprivileged user to read root-owned files, potentially leading to privilege escalation. This flaw affects util-linux versions prior to 2.37.4.

### CVE-2022-0563

- **Package:** `mount`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2022-0563](https://security-tracker.debian.org/tracker/CVE-2022-0563)

A flaw was found in the util-linux chfn and chsh utilities when compiled with Readline support. The Readline library uses an "INPUTRC" environment variable to get a path to the library config file. When the library cannot parse the specified file, it prints an error message containing data from the file. This flaw allows an unprivileged user to read root-owned files, potentially leading to privilege escalation. This flaw affects util-linux versions prior to 2.37.4.

### CVE-2022-0563

- **Package:** `util-linux`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2022-0563](https://security-tracker.debian.org/tracker/CVE-2022-0563)

A flaw was found in the util-linux chfn and chsh utilities when compiled with Readline support. The Readline library uses an "INPUTRC" environment variable to get a path to the library config file. When the library cannot parse the specified file, it prints an error message containing data from the file. This flaw allows an unprivileged user to read root-owned files, potentially leading to privilege escalation. This flaw affects util-linux versions prior to 2.37.4.

### CVE-2022-0563

- **Package:** `util-linux-extra`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2022-0563](https://security-tracker.debian.org/tracker/CVE-2022-0563)

A flaw was found in the util-linux chfn and chsh utilities when compiled with Readline support. The Readline library uses an "INPUTRC" environment variable to get a path to the library config file. When the library cannot parse the specified file, it prints an error message containing data from the file. This flaw allows an unprivileged user to read root-owned files, potentially leading to privilege escalation. This flaw affects util-linux versions prior to 2.37.4.

### CVE-2023-31439

- **Package:** `libsystemd0`
- **Installed:** `252.39-1~deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2023-31439](https://security-tracker.debian.org/tracker/CVE-2023-31439)

An issue was discovered in systemd 253. An attacker can modify the contents of past events in a sealed log file and then adjust the file such that checking the integrity shows no error, despite modifications. NOTE: the vendor reportedly sent "a reply denying that any of the finding was a security vulnerability."

### CVE-2023-31439

- **Package:** `libudev1`
- **Installed:** `252.39-1~deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2023-31439](https://security-tracker.debian.org/tracker/CVE-2023-31439)

An issue was discovered in systemd 253. An attacker can modify the contents of past events in a sealed log file and then adjust the file such that checking the integrity shows no error, despite modifications. NOTE: the vendor reportedly sent "a reply denying that any of the finding was a security vulnerability."

### CVE-2017-18018

- **Package:** `coreutils`
- **Installed:** `9.1-1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2017-18018](https://security-tracker.debian.org/tracker/CVE-2017-18018)

In GNU Coreutils through 8.29, chown-core.c in chown and chgrp does not prevent replacement of a plain file with a symlink during use of the POSIX "-R -L" options, which allows local users to modify the ownership of arbitrary files by leveraging a race condition.

### CVE-2023-31437

- **Package:** `libsystemd0`
- **Installed:** `252.39-1~deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2023-31437](https://security-tracker.debian.org/tracker/CVE-2023-31437)

An issue was discovered in systemd 253. An attacker can modify a sealed log file such that, in some views, not all existing and sealed log messages are displayed. NOTE: the vendor reportedly sent "a reply denying that any of the finding was a security vulnerability."

### CVE-2023-31437

- **Package:** `libudev1`
- **Installed:** `252.39-1~deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2023-31437](https://security-tracker.debian.org/tracker/CVE-2023-31437)

An issue was discovered in systemd 253. An attacker can modify a sealed log file such that, in some views, not all existing and sealed log messages are displayed. NOTE: the vendor reportedly sent "a reply denying that any of the finding was a security vulnerability."

### CVE-2026-53910

- **Package:** `diffutils`
- **Installed:** `1:3.8-4`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-53910](https://security-tracker.debian.org/tracker/CVE-2026-53910)

diff3 tool from GNU diffutils is vulnerable to a heap‑based buffer overflow due to multiple signed integer overflows in line‑mapping calculations. Incorrect arithmetic in mapping line ranges can result in corrupted values being used for memory allocation and loop bounds. When processing crafted diff output, these overflows may cause the application to allocate insufficient memory and subsequently perform out‑of‑bounds writes during internal processing.  An attacker who can control the output of the diff program used by diff3 (e.g. via --diff-program pointing to a malicious script) can trigger out-of-bounds writes, resulting in a crash and potentially remote code execution depending on the environment.   This issue has been fixed in commit 9ff04d5b84743e331e80b589335a52c5480d1815   NOTE: The project maintainers claim that this is not a security issue. They state that the worst outcome this issue can cause is a crash of diff and that it cannot be used to escalate privileges.

### CVE-2023-31438

- **Package:** `libsystemd0`
- **Installed:** `252.39-1~deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2023-31438](https://security-tracker.debian.org/tracker/CVE-2023-31438)

An issue was discovered in systemd 253. An attacker can truncate a sealed log file and then resume log sealing such that checking the integrity shows no error, despite modifications. NOTE: the vendor reportedly sent "a reply denying that any of the finding was a security vulnerability."

### CVE-2023-31438

- **Package:** `libudev1`
- **Installed:** `252.39-1~deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2023-31438](https://security-tracker.debian.org/tracker/CVE-2023-31438)

An issue was discovered in systemd 253. An attacker can truncate a sealed log file and then resume log sealing such that checking the integrity shows no error, despite modifications. NOTE: the vendor reportedly sent "a reply denying that any of the finding was a security vulnerability."

### CVE-2025-5278

- **Package:** `coreutils`
- **Installed:** `9.1-1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-5278](https://security-tracker.debian.org/tracker/CVE-2025-5278)

A flaw was found in GNU Coreutils. The sort utility's begfield() function is vulnerable to a heap buffer under-read. The program may access memory outside the allocated buffer if a user runs a crafted command using the traditional key format. A malicious input could lead to a crash or leak sensitive data.

### CVE-2022-3219

- **Package:** `gpgv`
- **Installed:** `2.2.40-1.1+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2022-3219](https://security-tracker.debian.org/tracker/CVE-2022-3219)

GnuPG can be made to spin on a relatively small input by (for example) crafting a public key with thousands of signatures attached, compressed down to just a few KB.

### CVE-2026-11850

- **Package:** `libgssapi-krb5-2`
- **Installed:** `1.20.1-2+deb12u5`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-11850](https://security-tracker.debian.org/tracker/CVE-2026-11850)

An integer underflow vulnerability was found in MIT krb5 in the berval2tl_data() function in plugins/kdb/ldap/libkdb_ldap/ldap_principal2.c. The function performs an unsigned subtraction (bv_len - 2) without a prior bounds check. When bv_len is 0 or 1, the subtraction wraps to a large value which is then truncated to uint16_t, yielding 0xFFFE (65534) or 0xFFFF (65535). The subsequent malloc succeeds and memcpy reads up to 65534 bytes from a 0-1 byte buffer, resulting in a heap out-of-bounds read. The attack vector involves a malicious or compromised LDAP KDB backend returning a krbExtraData attribute with bv_len < 2, triggering the underflow when the KDC or kadmind reads principal data.

### CVE-2026-11850

- **Package:** `libk5crypto3`
- **Installed:** `1.20.1-2+deb12u5`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-11850](https://security-tracker.debian.org/tracker/CVE-2026-11850)

An integer underflow vulnerability was found in MIT krb5 in the berval2tl_data() function in plugins/kdb/ldap/libkdb_ldap/ldap_principal2.c. The function performs an unsigned subtraction (bv_len - 2) without a prior bounds check. When bv_len is 0 or 1, the subtraction wraps to a large value which is then truncated to uint16_t, yielding 0xFFFE (65534) or 0xFFFF (65535). The subsequent malloc succeeds and memcpy reads up to 65534 bytes from a 0-1 byte buffer, resulting in a heap out-of-bounds read. The attack vector involves a malicious or compromised LDAP KDB backend returning a krbExtraData attribute with bv_len < 2, triggering the underflow when the KDC or kadmind reads principal data.

### CVE-2026-11850

- **Package:** `libkrb5-3`
- **Installed:** `1.20.1-2+deb12u5`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-11850](https://security-tracker.debian.org/tracker/CVE-2026-11850)

An integer underflow vulnerability was found in MIT krb5 in the berval2tl_data() function in plugins/kdb/ldap/libkdb_ldap/ldap_principal2.c. The function performs an unsigned subtraction (bv_len - 2) without a prior bounds check. When bv_len is 0 or 1, the subtraction wraps to a large value which is then truncated to uint16_t, yielding 0xFFFE (65534) or 0xFFFF (65535). The subsequent malloc succeeds and memcpy reads up to 65534 bytes from a 0-1 byte buffer, resulting in a heap out-of-bounds read. The attack vector involves a malicious or compromised LDAP KDB backend returning a krbExtraData attribute with bv_len < 2, triggering the underflow when the KDC or kadmind reads principal data.

### CVE-2026-11850

- **Package:** `libkrb5support0`
- **Installed:** `1.20.1-2+deb12u5`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-11850](https://security-tracker.debian.org/tracker/CVE-2026-11850)

An integer underflow vulnerability was found in MIT krb5 in the berval2tl_data() function in plugins/kdb/ldap/libkdb_ldap/ldap_principal2.c. The function performs an unsigned subtraction (bv_len - 2) without a prior bounds check. When bv_len is 0 or 1, the subtraction wraps to a large value which is then truncated to uint16_t, yielding 0xFFFE (65534) or 0xFFFF (65535). The subsequent malloc succeeds and memcpy reads up to 65534 bytes from a 0-1 byte buffer, resulting in a heap out-of-bounds read. The attack vector involves a malicious or compromised LDAP KDB backend returning a krbExtraData attribute with bv_len < 2, triggering the underflow when the KDC or kadmind reads principal data.

### CVE-2026-95209

- **Package:** `libgnutls30`
- **Installed:** `3.7.9-2+deb12u7`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-95209](https://security-tracker.debian.org/tracker/CVE-2026-95209)

An issue in gnutls v3.8.13 causes legitimate CA certificates to be rejected, leading to a Denial of Service (DoS).

### CVE-2025-29088

- **Package:** `libsqlite3-0`
- **Installed:** `3.40.1-2+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-29088](https://security-tracker.debian.org/tracker/CVE-2025-29088)

In SQLite 3.49.0 before 3.49.1, certain argument values to sqlite3_db_config (in the C-language API) can cause a denial of service (application crash). An sz*nBig multiplication is not cast to a 64-bit integer, and consequently some memory allocations may be incorrect.

### CVE-2025-29088

- **Package:** `sqlite3`
- **Installed:** `3.40.1-2+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-29088](https://security-tracker.debian.org/tracker/CVE-2025-29088)

In SQLite 3.49.0 before 3.49.1, certain argument values to sqlite3_db_config (in the C-language API) can cause a denial of service (application crash). An sz*nBig multiplication is not cast to a 64-bit integer, and consequently some memory allocations may be incorrect.

### CVE-2026-88647

- **Package:** `libgnutls30`
- **Installed:** `3.7.9-2+deb12u7`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-88647](https://security-tracker.debian.org/tracker/CVE-2026-88647)

A hostname verification bypass in GnuTLS v3.8.13 allows attackers to circumvent the Common Name fallback mechanism and eavesdrop on communications via a crafted certificate.

### CVE-2025-14104

- **Package:** `bsdutils`
- **Installed:** `1:2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-14104](https://security-tracker.debian.org/tracker/CVE-2025-14104)

A flaw was found in util-linux. This vulnerability allows a heap buffer overread when processing 256-byte usernames, specifically within the `setpwnam()` function, affecting SUID (Set User ID) login-utils utilities writing to the password database.

### CVE-2025-14104

- **Package:** `libblkid1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-14104](https://security-tracker.debian.org/tracker/CVE-2025-14104)

A flaw was found in util-linux. This vulnerability allows a heap buffer overread when processing 256-byte usernames, specifically within the `setpwnam()` function, affecting SUID (Set User ID) login-utils utilities writing to the password database.

### CVE-2025-14104

- **Package:** `libmount1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-14104](https://security-tracker.debian.org/tracker/CVE-2025-14104)

A flaw was found in util-linux. This vulnerability allows a heap buffer overread when processing 256-byte usernames, specifically within the `setpwnam()` function, affecting SUID (Set User ID) login-utils utilities writing to the password database.

### CVE-2025-14104

- **Package:** `libsmartcols1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-14104](https://security-tracker.debian.org/tracker/CVE-2025-14104)

A flaw was found in util-linux. This vulnerability allows a heap buffer overread when processing 256-byte usernames, specifically within the `setpwnam()` function, affecting SUID (Set User ID) login-utils utilities writing to the password database.

### CVE-2025-14104

- **Package:** `libuuid1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-14104](https://security-tracker.debian.org/tracker/CVE-2025-14104)

A flaw was found in util-linux. This vulnerability allows a heap buffer overread when processing 256-byte usernames, specifically within the `setpwnam()` function, affecting SUID (Set User ID) login-utils utilities writing to the password database.

### CVE-2025-14104

- **Package:** `mount`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-14104](https://security-tracker.debian.org/tracker/CVE-2025-14104)

A flaw was found in util-linux. This vulnerability allows a heap buffer overread when processing 256-byte usernames, specifically within the `setpwnam()` function, affecting SUID (Set User ID) login-utils utilities writing to the password database.

### CVE-2025-14104

- **Package:** `util-linux`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-14104](https://security-tracker.debian.org/tracker/CVE-2025-14104)

A flaw was found in util-linux. This vulnerability allows a heap buffer overread when processing 256-byte usernames, specifically within the `setpwnam()` function, affecting SUID (Set User ID) login-utils utilities writing to the password database.

### CVE-2025-14104

- **Package:** `util-linux-extra`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-14104](https://security-tracker.debian.org/tracker/CVE-2025-14104)

A flaw was found in util-linux. This vulnerability allows a heap buffer overread when processing 256-byte usernames, specifically within the `setpwnam()` function, affecting SUID (Set User ID) login-utils utilities writing to the password database.

### CVE-2026-88648

- **Package:** `libgnutls30`
- **Installed:** `3.7.9-2+deb12u7`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-88648](https://security-tracker.debian.org/tracker/CVE-2026-88648)

Incomplete X.509 implementation in GnuTLS v3.8.13 allows attackers controlling a subordinate Certificate Authority to bypass cross-domain PKI restrictions and issue unauthorized certificates.

### CVE-2026-56392

- **Package:** `coreutils`
- **Installed:** `9.1-1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-56392](https://security-tracker.debian.org/tracker/CVE-2026-56392)

GNU coreutils unexpand is vulnerable to a heap-based buffer overflow due to an integer overflow during buffer allocation when processing large tab stop (-t) values. The multiplication used to calculate the allocation size can wrap around, resulting in an undersized buffer. When processing crafted input, subsequent writes exceed the allocated memory, leading to an out‑of‑bounds heap write.  When running GNU coreutils unexpand with attacker-provided large tab stop (-t) arguments, this behavior leads to a crash and potentially achieve a heap write primitive depending on memory layout.           This issue has been fixed in the commit b60a159fdc5bfcf9988d3a4cb6f53abe8ad5d35d

### CVE-2026-95184

- **Package:** `libgnutls30`
- **Installed:** `3.7.9-2+deb12u7`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-95184](https://security-tracker.debian.org/tracker/CVE-2026-95184)

Improper certificate validation in gnutls v3.8.13 causes the application to reject legitimate certificates for valid users, leading to a Denial of Service (DoS).

### CVE-2026-95210

- **Package:** `libgnutls30`
- **Installed:** `3.7.9-2+deb12u7`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-95210](https://security-tracker.debian.org/tracker/CVE-2026-95210)

Improper certificate validation in gnutls v3.8.13 causes the application to accept certificates containing invalid extensions.

### CVE-2026-67693

- **Package:** `libgnutls30`
- **Installed:** `3.7.9-2+deb12u7`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-67693](https://security-tracker.debian.org/tracker/CVE-2026-67693)

An issue in gnutls v.3.8.13 allows an attacker to obtain sensitive information via failing to reject end-entity X.509 certificates that contain a contradictory combination of Key Usage (KU) and Extended Key Usage (EKU)

### CVE-2026-56391

- **Package:** `coreutils`
- **Installed:** `9.1-1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-56391](https://security-tracker.debian.org/tracker/CVE-2026-56391)

GNU coreutils uniq is vulnerable to an out‑of‑bounds read due to incorrect handling of multibyte input when the -w (--check-chars) option is used. The find_field() function miscalculates the byte length of characters by repeatedly processing a fixed pointer instead of advancing through the input, resulting in an inflated length value.  This incorrect length is later used in a memcmp operation, causing reads beyond the allocated buffer when processing crafted multibyte input.  When running GNU coreutils uniq with attacker-provided arguments, this behavior leads to a crash and potential adjacent heap memory exposure.   This issue has been fixed in the commit d64e35a8a4c0e4608321433e0d84d917e4e36371.

### CVE-2026-102474

- **Package:** `dash`
- **Installed:** `0.5.12-2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-102474](https://security-tracker.debian.org/tracker/CVE-2026-102474)

A flaw was found in dash. The printf builtin reserves four bytes before converting a Unicode \u or \U escape, but the multi-byte token can need five or six bytes. A local user who can supply such an escape to dash printf or echo %b, including through dash -c and a positional argument, can write one or two bytes past that reservation.

### CVE-2026-102473

- **Package:** `dash`
- **Installed:** `0.5.12-2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-102473](https://security-tracker.debian.org/tracker/CVE-2026-102473)

A flaw was found in dash. When built without libc fnmatch, the internal pmatch() matcher implements * by unbounded recursion over candidate positions. A local user who can plant filenames, or otherwise feed that matcher, can make a short multi-star pattern such as *.*.*.*.*.tar.gz consume excessive CPU.

### CVE-2026-106584

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-106584](https://security-tracker.debian.org/tracker/CVE-2026-106584)

In ssh-keygen in OpenSSH before 10.6, certificates could have incorrect expiration times because of Daylight Saving mishandling. There can be a slightly more severe effect on users in certain Antarctic locations.

---

# Trivy (Aqua Security)

**Duration:** 4.6s

## Summary

**4 Critical** | **66 High** | 112 Medium | 120 Low | 4 Unknown

**Total:** 306 vulnerabilities

## Critical (4)

### CVE-2025-7458

- **Package:** `libsqlite3-0`
- **Installed:** `3.40.1-2+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-7458](https://avd.aquasec.com/nvd/cve-2025-7458)

An integer overflow in the sqlite3KeyInfoFromExprList function in SQLite versions 3.39.2 through 3.41.1 allows an attacker with the ability to execute arbitrary SQL statements to cause a denial of service or disclose sensitive information from process memory via a crafted SELECT statement with a large number of expressions in the ORDER BY clause.

### CVE-2026-60002

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-60002](https://avd.aquasec.com/nvd/cve-2026-60002)

ssh in OpenSSH before 10.4 can have a use-after-free when a server changes its host key during a key re-exchange. (This outcome occurs only on the client side.)

### CVE-2025-7458

- **Package:** `sqlite3`
- **Installed:** `3.40.1-2+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-7458](https://avd.aquasec.com/nvd/cve-2025-7458)

An integer overflow in the sqlite3KeyInfoFromExprList function in SQLite versions 3.39.2 through 3.41.1 allows an attacker with the ability to execute arbitrary SQL statements to cause a denial of service or disclose sensitive information from process memory via a crafted SELECT statement with a large number of expressions in the ORDER BY clause.

### CVE-2023-45853

- **Package:** `zlib1g`
- **Installed:** `1:1.2.13.dfsg-1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2023-45853](https://avd.aquasec.com/nvd/cve-2023-45853)

MiniZip in zlib through 1.3 has an integer overflow and resultant heap-based buffer overflow in zipOpenNewFileInZip4_64 via a long filename, comment, or extra field. NOTE: MiniZip is not a supported part of the zlib product. NOTE: pyminizip through 0.2.6 is also vulnerable because it bundles an affected zlib version, and exposes the applicable MiniZip code through its compress API.

## High (66)

### CVE-2026-53613

- **Package:** `bsdutils`
- **Installed:** `1:2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-53613](https://avd.aquasec.com/nvd/cve-2026-53613)

util-linux is a random collection of Linux utilities. In util-linux 2.17 through 2.41.6 and 2.42 through 2.42.3, and in 2.42.4 when the legacy `mount(2)` path is used without `/proc`, restricted non-root `mount` requests validate an `/etc/fstab` target before the mount operation re-resolves that pathname. A local low-privileged user authorized by an fstab `user` or `users` entry whose target has an attacker-writable ancestor can use `renameat2(RENAME_EXCHANGE)` to swap a path component and redirect an authorized mount to a root-owned location, such as mounting attacker-controlled content over `/etc/sudoers.d`, and thereby gain root privileges. Versions 2.41.5 and 2.42.2 pin targets for the new mount API, and 2.42.4 pins legacy targets through `/proc/self/fd`; the documented legacy fallback without `/proc` remains affected.

### CVE-2026-53615

- **Package:** `bsdutils`
- **Installed:** `1:2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-53615](https://avd.aquasec.com/nvd/cve-2026-53615)

util-linux is a random collection of Linux utilities. Before util-linux 2.41.4, `parse_dos_extended()` in `libblkid/src/partitions/dos.c` computes an extended-partition start sector with 32-bit addition and does not apply the extended-area bounds checks to the first two EBR entries. A local attacker who causes a crafted DOS extended-partition disk image or removable medium to be probed can wrap `cur_start + start` to sector zero and cause libblkid to report a false partition overlapping the MBR. This directly compromises the integrity of the reported partition metadata; disk modification or availability loss requires a separate downstream consumer to act on that metadata. This issue is fixed in 2.41.4.

### CVE-2026-76642

- **Package:** `bsdutils`
- **Installed:** `1:2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-76642](https://avd.aquasec.com/nvd/cve-2026-76642)

util-linux versions through 2.41.5 and 2.42.2 fail to check mount helper exit status before running post-mount hooks, allowing unprivileged users to execute privileged operations on pre-existing filesystems. Attackers can exploit X-mount.idmap or X-mount.owner hooks to clone filesystems with inherited suid bits or modify target inode permissions after a helper fails, achieving privilege escalation.

### CVE-2026-78408

- **Package:** `bsdutils`
- **Installed:** `1:2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-78408](https://avd.aquasec.com/nvd/cve-2026-78408)

The nsenter --join-cgroup option opens the target cgroup.procs file as root and leaves that file descriptor open across later namespace and credential changes and across execve(). Because the kernel checks later cgroup migrations using the credentials from the original open, a program run in an attacker-controlled target can inherit root's ability to move host processes between cgroups. After a privileged operator uses --join-cgroup against that target, an unprivileged user can migrate and terminate unrelated root processes.

### CVE-2026-78409

- **Package:** `bsdutils`
- **Installed:** `1:2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-78409](https://avd.aquasec.com/nvd/cve-2026-78409)

The X-mount.subdir option uses a detached-tree fast path on Linux 6.15 and later and passes the configured subdirectory to open_tree() with AT_SYMLINK_NOFOLLOW. That flag does not stop intermediate symlink traversal or keep resolution inside the newly mounted filesystem. A local unprivileged user with an fstab-authorized X-mount.subdir entry can attach a host path at the intended mountpoint.

### CVE-2026-78410

- **Package:** `bsdutils`
- **Installed:** `1:2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-78410](https://avd.aquasec.com/nvd/cve-2026-78410)

A flaw was found in util-linux. Restricted bind mounts take the source path from fstab but do not pin that source before the privileged mount. A local unprivileged user who can replace the authorized source or a writable ancestor can redirect SUID mount(8) to bind another host directory. If the fstab entry also sets X-mount.owner, X-mount.group, or X-mount.mode, root then changes ownership or mode on that redirected inode.

### CVE-2026-41992

- **Package:** `gzip`
- **Installed:** `1.12-1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-41992](https://avd.aquasec.com/nvd/cve-2026-41992)

GNU gzip contains a global buffer overflow vulnerability in the LZH decompression logic caused by improper reuse of shared global state between different decompression formats within a single execution. GNU gzip maintains a global array that is shared across the LZ77, LZW, and LZH decompression routines and is not reinitialized between files processed in the same invocation.
By decompressing a specially crafted LZW file followed by a specially crafted LZH file in a single gzip -d command, an attacker can poison the shared global state and subsequently trigger an out‑of‑bounds read in the LZH decoder. The LZH decompression logic follows stale values left in the shared array, causing reads past the end of the allocated global buffer.

This issue has been fixed in commits 63dbf6b3b9e6e781df1a6a64e609b10e23969681 and e7378c2d421be6a286922374425680bbe9ad8b7d.

### CVE-2026-54369

- **Package:** `libacl1`
- **Installed:** `2.3.1-3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-54369](https://avd.aquasec.com/nvd/cve-2026-54369)

acl before version 2.4.0 contains a symlink traversal vulnerability in the libacl pathname-based functions acl_get_file(), acl_set_file(), acl_extended_file(), and acl_delete_def_file() that allows local attackers to escalate privileges by replacing any pathname component with a symbolic link. Attackers who control any component of a pathname processed by a privileged caller can redirect ACL read or write operations to arbitrary files or directories, enabling unauthorized manipulation of access control lists and local privilege escalation.

### CVE-2026-53613

- **Package:** `libblkid1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-53613](https://avd.aquasec.com/nvd/cve-2026-53613)

util-linux is a random collection of Linux utilities. In util-linux 2.17 through 2.41.6 and 2.42 through 2.42.3, and in 2.42.4 when the legacy `mount(2)` path is used without `/proc`, restricted non-root `mount` requests validate an `/etc/fstab` target before the mount operation re-resolves that pathname. A local low-privileged user authorized by an fstab `user` or `users` entry whose target has an attacker-writable ancestor can use `renameat2(RENAME_EXCHANGE)` to swap a path component and redirect an authorized mount to a root-owned location, such as mounting attacker-controlled content over `/etc/sudoers.d`, and thereby gain root privileges. Versions 2.41.5 and 2.42.2 pin targets for the new mount API, and 2.42.4 pins legacy targets through `/proc/self/fd`; the documented legacy fallback without `/proc` remains affected.

### CVE-2026-53615

- **Package:** `libblkid1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-53615](https://avd.aquasec.com/nvd/cve-2026-53615)

util-linux is a random collection of Linux utilities. Before util-linux 2.41.4, `parse_dos_extended()` in `libblkid/src/partitions/dos.c` computes an extended-partition start sector with 32-bit addition and does not apply the extended-area bounds checks to the first two EBR entries. A local attacker who causes a crafted DOS extended-partition disk image or removable medium to be probed can wrap `cur_start + start` to sector zero and cause libblkid to report a false partition overlapping the MBR. This directly compromises the integrity of the reported partition metadata; disk modification or availability loss requires a separate downstream consumer to act on that metadata. This issue is fixed in 2.41.4.

### CVE-2026-76642

- **Package:** `libblkid1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-76642](https://avd.aquasec.com/nvd/cve-2026-76642)

util-linux versions through 2.41.5 and 2.42.2 fail to check mount helper exit status before running post-mount hooks, allowing unprivileged users to execute privileged operations on pre-existing filesystems. Attackers can exploit X-mount.idmap or X-mount.owner hooks to clone filesystems with inherited suid bits or modify target inode permissions after a helper fails, achieving privilege escalation.

### CVE-2026-78408

- **Package:** `libblkid1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-78408](https://avd.aquasec.com/nvd/cve-2026-78408)

The nsenter --join-cgroup option opens the target cgroup.procs file as root and leaves that file descriptor open across later namespace and credential changes and across execve(). Because the kernel checks later cgroup migrations using the credentials from the original open, a program run in an attacker-controlled target can inherit root's ability to move host processes between cgroups. After a privileged operator uses --join-cgroup against that target, an unprivileged user can migrate and terminate unrelated root processes.

### CVE-2026-78409

- **Package:** `libblkid1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-78409](https://avd.aquasec.com/nvd/cve-2026-78409)

The X-mount.subdir option uses a detached-tree fast path on Linux 6.15 and later and passes the configured subdirectory to open_tree() with AT_SYMLINK_NOFOLLOW. That flag does not stop intermediate symlink traversal or keep resolution inside the newly mounted filesystem. A local unprivileged user with an fstab-authorized X-mount.subdir entry can attach a host path at the intended mountpoint.

### CVE-2026-78410

- **Package:** `libblkid1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-78410](https://avd.aquasec.com/nvd/cve-2026-78410)

A flaw was found in util-linux. Restricted bind mounts take the source path from fstab but do not pin that source before the privileged mount. A local unprivileged user who can replace the authorized source or a writable ancestor can redirect SUID mount(8) to bind another host directory. If the fstab entry also sets X-mount.owner, X-mount.group, or X-mount.mode, root then changes ownership or mode on that redirected inode.

### CVE-2026-53613

- **Package:** `libmount1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-53613](https://avd.aquasec.com/nvd/cve-2026-53613)

util-linux is a random collection of Linux utilities. In util-linux 2.17 through 2.41.6 and 2.42 through 2.42.3, and in 2.42.4 when the legacy `mount(2)` path is used without `/proc`, restricted non-root `mount` requests validate an `/etc/fstab` target before the mount operation re-resolves that pathname. A local low-privileged user authorized by an fstab `user` or `users` entry whose target has an attacker-writable ancestor can use `renameat2(RENAME_EXCHANGE)` to swap a path component and redirect an authorized mount to a root-owned location, such as mounting attacker-controlled content over `/etc/sudoers.d`, and thereby gain root privileges. Versions 2.41.5 and 2.42.2 pin targets for the new mount API, and 2.42.4 pins legacy targets through `/proc/self/fd`; the documented legacy fallback without `/proc` remains affected.

### CVE-2026-53615

- **Package:** `libmount1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-53615](https://avd.aquasec.com/nvd/cve-2026-53615)

util-linux is a random collection of Linux utilities. Before util-linux 2.41.4, `parse_dos_extended()` in `libblkid/src/partitions/dos.c` computes an extended-partition start sector with 32-bit addition and does not apply the extended-area bounds checks to the first two EBR entries. A local attacker who causes a crafted DOS extended-partition disk image or removable medium to be probed can wrap `cur_start + start` to sector zero and cause libblkid to report a false partition overlapping the MBR. This directly compromises the integrity of the reported partition metadata; disk modification or availability loss requires a separate downstream consumer to act on that metadata. This issue is fixed in 2.41.4.

### CVE-2026-76642

- **Package:** `libmount1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-76642](https://avd.aquasec.com/nvd/cve-2026-76642)

util-linux versions through 2.41.5 and 2.42.2 fail to check mount helper exit status before running post-mount hooks, allowing unprivileged users to execute privileged operations on pre-existing filesystems. Attackers can exploit X-mount.idmap or X-mount.owner hooks to clone filesystems with inherited suid bits or modify target inode permissions after a helper fails, achieving privilege escalation.

### CVE-2026-78408

- **Package:** `libmount1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-78408](https://avd.aquasec.com/nvd/cve-2026-78408)

The nsenter --join-cgroup option opens the target cgroup.procs file as root and leaves that file descriptor open across later namespace and credential changes and across execve(). Because the kernel checks later cgroup migrations using the credentials from the original open, a program run in an attacker-controlled target can inherit root's ability to move host processes between cgroups. After a privileged operator uses --join-cgroup against that target, an unprivileged user can migrate and terminate unrelated root processes.

### CVE-2026-78409

- **Package:** `libmount1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-78409](https://avd.aquasec.com/nvd/cve-2026-78409)

The X-mount.subdir option uses a detached-tree fast path on Linux 6.15 and later and passes the configured subdirectory to open_tree() with AT_SYMLINK_NOFOLLOW. That flag does not stop intermediate symlink traversal or keep resolution inside the newly mounted filesystem. A local unprivileged user with an fstab-authorized X-mount.subdir entry can attach a host path at the intended mountpoint.

### CVE-2026-78410

- **Package:** `libmount1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-78410](https://avd.aquasec.com/nvd/cve-2026-78410)

A flaw was found in util-linux. Restricted bind mounts take the source path from fstab but do not pin that source before the privileged mount. A local unprivileged user who can replace the authorized source or a writable ancestor can redirect SUID mount(8) to bind another host directory. If the fstab entry also sets X-mount.owner, X-mount.group, or X-mount.mode, root then changes ownership or mode on that redirected inode.

### CVE-2025-69720

- **Package:** `libncursesw6`
- **Installed:** `6.4-4`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-69720](https://avd.aquasec.com/nvd/cve-2025-69720)

The infocmp command-line tool in ncurses before 6.5-20251213 has a stack-based buffer overflow in analyze_string in progs/infocmp.c.

### CVE-2026-53613

- **Package:** `libsmartcols1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-53613](https://avd.aquasec.com/nvd/cve-2026-53613)

util-linux is a random collection of Linux utilities. In util-linux 2.17 through 2.41.6 and 2.42 through 2.42.3, and in 2.42.4 when the legacy `mount(2)` path is used without `/proc`, restricted non-root `mount` requests validate an `/etc/fstab` target before the mount operation re-resolves that pathname. A local low-privileged user authorized by an fstab `user` or `users` entry whose target has an attacker-writable ancestor can use `renameat2(RENAME_EXCHANGE)` to swap a path component and redirect an authorized mount to a root-owned location, such as mounting attacker-controlled content over `/etc/sudoers.d`, and thereby gain root privileges. Versions 2.41.5 and 2.42.2 pin targets for the new mount API, and 2.42.4 pins legacy targets through `/proc/self/fd`; the documented legacy fallback without `/proc` remains affected.

### CVE-2026-53615

- **Package:** `libsmartcols1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-53615](https://avd.aquasec.com/nvd/cve-2026-53615)

util-linux is a random collection of Linux utilities. Before util-linux 2.41.4, `parse_dos_extended()` in `libblkid/src/partitions/dos.c` computes an extended-partition start sector with 32-bit addition and does not apply the extended-area bounds checks to the first two EBR entries. A local attacker who causes a crafted DOS extended-partition disk image or removable medium to be probed can wrap `cur_start + start` to sector zero and cause libblkid to report a false partition overlapping the MBR. This directly compromises the integrity of the reported partition metadata; disk modification or availability loss requires a separate downstream consumer to act on that metadata. This issue is fixed in 2.41.4.

### CVE-2026-76642

- **Package:** `libsmartcols1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-76642](https://avd.aquasec.com/nvd/cve-2026-76642)

util-linux versions through 2.41.5 and 2.42.2 fail to check mount helper exit status before running post-mount hooks, allowing unprivileged users to execute privileged operations on pre-existing filesystems. Attackers can exploit X-mount.idmap or X-mount.owner hooks to clone filesystems with inherited suid bits or modify target inode permissions after a helper fails, achieving privilege escalation.

### CVE-2026-78408

- **Package:** `libsmartcols1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-78408](https://avd.aquasec.com/nvd/cve-2026-78408)

The nsenter --join-cgroup option opens the target cgroup.procs file as root and leaves that file descriptor open across later namespace and credential changes and across execve(). Because the kernel checks later cgroup migrations using the credentials from the original open, a program run in an attacker-controlled target can inherit root's ability to move host processes between cgroups. After a privileged operator uses --join-cgroup against that target, an unprivileged user can migrate and terminate unrelated root processes.

### CVE-2026-78409

- **Package:** `libsmartcols1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-78409](https://avd.aquasec.com/nvd/cve-2026-78409)

The X-mount.subdir option uses a detached-tree fast path on Linux 6.15 and later and passes the configured subdirectory to open_tree() with AT_SYMLINK_NOFOLLOW. That flag does not stop intermediate symlink traversal or keep resolution inside the newly mounted filesystem. A local unprivileged user with an fstab-authorized X-mount.subdir entry can attach a host path at the intended mountpoint.

### CVE-2026-78410

- **Package:** `libsmartcols1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-78410](https://avd.aquasec.com/nvd/cve-2026-78410)

A flaw was found in util-linux. Restricted bind mounts take the source path from fstab but do not pin that source before the privileged mount. A local unprivileged user who can replace the authorized source or a writable ancestor can redirect SUID mount(8) to bind another host directory. If the fstab entry also sets X-mount.owner, X-mount.group, or X-mount.mode, root then changes ownership or mode on that redirected inode.

### CVE-2026-11822

- **Package:** `libsqlite3-0`
- **Installed:** `3.40.1-2+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-11822](https://avd.aquasec.com/nvd/cve-2026-11822)

SQLite before 3.53.2 contains an out-of-bounds read vulnerability in the FTS5 full-text search extension that allows attackers to crash the process by supplying a crafted database with a malformed FTS5 leaf page. Attackers can set an oversized term length in the leaf page so that fts5LeafSeek() reads past the end of the page buffer while comparing terms during an FTS5 MATCH query, in applications compiled with SQLITE_ENABLE_FTS5.

### CVE-2026-11824

- **Package:** `libsqlite3-0`
- **Installed:** `3.40.1-2+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-11824](https://avd.aquasec.com/nvd/cve-2026-11824)

SQLite before 3.53.2 contains a heap-based buffer overflow vulnerability in the FTS5 full-text search extension that allows attackers to cause a crash or execute arbitrary code by supplying a crafted database with malicious continuation page metadata specifying a szLeaf value smaller than 4. Attackers can trigger an integer underflow in fts5ChunkIterate() causing an inflated remaining byte count during FTS5 MATCH query processing, leading to a heap buffer overflow of attacker-controlled data in applications compiled with SQLITE_ENABLE_FTS5.

### CVE-2026-16742

- **Package:** `libsystemd0`
- **Installed:** `252.39-1~deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-16742](https://avd.aquasec.com/nvd/cve-2026-16742)

systemd-homed contains a local privilege escalation bug via arbitrary system group addition to a local, logged in, homed-managed user

### CVE-2025-69720

- **Package:** `libtinfo6`
- **Installed:** `6.4-4`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-69720](https://avd.aquasec.com/nvd/cve-2025-69720)

The infocmp command-line tool in ncurses before 6.5-20251213 has a stack-based buffer overflow in analyze_string in progs/infocmp.c.

### CVE-2026-16742

- **Package:** `libudev1`
- **Installed:** `252.39-1~deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-16742](https://avd.aquasec.com/nvd/cve-2026-16742)

systemd-homed contains a local privilege escalation bug via arbitrary system group addition to a local, logged in, homed-managed user

### CVE-2026-53613

- **Package:** `libuuid1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-53613](https://avd.aquasec.com/nvd/cve-2026-53613)

util-linux is a random collection of Linux utilities. In util-linux 2.17 through 2.41.6 and 2.42 through 2.42.3, and in 2.42.4 when the legacy `mount(2)` path is used without `/proc`, restricted non-root `mount` requests validate an `/etc/fstab` target before the mount operation re-resolves that pathname. A local low-privileged user authorized by an fstab `user` or `users` entry whose target has an attacker-writable ancestor can use `renameat2(RENAME_EXCHANGE)` to swap a path component and redirect an authorized mount to a root-owned location, such as mounting attacker-controlled content over `/etc/sudoers.d`, and thereby gain root privileges. Versions 2.41.5 and 2.42.2 pin targets for the new mount API, and 2.42.4 pins legacy targets through `/proc/self/fd`; the documented legacy fallback without `/proc` remains affected.

### CVE-2026-53615

- **Package:** `libuuid1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-53615](https://avd.aquasec.com/nvd/cve-2026-53615)

util-linux is a random collection of Linux utilities. Before util-linux 2.41.4, `parse_dos_extended()` in `libblkid/src/partitions/dos.c` computes an extended-partition start sector with 32-bit addition and does not apply the extended-area bounds checks to the first two EBR entries. A local attacker who causes a crafted DOS extended-partition disk image or removable medium to be probed can wrap `cur_start + start` to sector zero and cause libblkid to report a false partition overlapping the MBR. This directly compromises the integrity of the reported partition metadata; disk modification or availability loss requires a separate downstream consumer to act on that metadata. This issue is fixed in 2.41.4.

### CVE-2026-76642

- **Package:** `libuuid1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-76642](https://avd.aquasec.com/nvd/cve-2026-76642)

util-linux versions through 2.41.5 and 2.42.2 fail to check mount helper exit status before running post-mount hooks, allowing unprivileged users to execute privileged operations on pre-existing filesystems. Attackers can exploit X-mount.idmap or X-mount.owner hooks to clone filesystems with inherited suid bits or modify target inode permissions after a helper fails, achieving privilege escalation.

### CVE-2026-78408

- **Package:** `libuuid1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-78408](https://avd.aquasec.com/nvd/cve-2026-78408)

The nsenter --join-cgroup option opens the target cgroup.procs file as root and leaves that file descriptor open across later namespace and credential changes and across execve(). Because the kernel checks later cgroup migrations using the credentials from the original open, a program run in an attacker-controlled target can inherit root's ability to move host processes between cgroups. After a privileged operator uses --join-cgroup against that target, an unprivileged user can migrate and terminate unrelated root processes.

### CVE-2026-78409

- **Package:** `libuuid1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-78409](https://avd.aquasec.com/nvd/cve-2026-78409)

The X-mount.subdir option uses a detached-tree fast path on Linux 6.15 and later and passes the configured subdirectory to open_tree() with AT_SYMLINK_NOFOLLOW. That flag does not stop intermediate symlink traversal or keep resolution inside the newly mounted filesystem. A local unprivileged user with an fstab-authorized X-mount.subdir entry can attach a host path at the intended mountpoint.

### CVE-2026-78410

- **Package:** `libuuid1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-78410](https://avd.aquasec.com/nvd/cve-2026-78410)

A flaw was found in util-linux. Restricted bind mounts take the source path from fstab but do not pin that source before the privileged mount. A local unprivileged user who can replace the authorized source or a writable ancestor can redirect SUID mount(8) to bind another host directory. If the fstab entry also sets X-mount.owner, X-mount.group, or X-mount.mode, root then changes ownership or mode on that redirected inode.

### CVE-2026-53613

- **Package:** `mount`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-53613](https://avd.aquasec.com/nvd/cve-2026-53613)

util-linux is a random collection of Linux utilities. In util-linux 2.17 through 2.41.6 and 2.42 through 2.42.3, and in 2.42.4 when the legacy `mount(2)` path is used without `/proc`, restricted non-root `mount` requests validate an `/etc/fstab` target before the mount operation re-resolves that pathname. A local low-privileged user authorized by an fstab `user` or `users` entry whose target has an attacker-writable ancestor can use `renameat2(RENAME_EXCHANGE)` to swap a path component and redirect an authorized mount to a root-owned location, such as mounting attacker-controlled content over `/etc/sudoers.d`, and thereby gain root privileges. Versions 2.41.5 and 2.42.2 pin targets for the new mount API, and 2.42.4 pins legacy targets through `/proc/self/fd`; the documented legacy fallback without `/proc` remains affected.

### CVE-2026-53615

- **Package:** `mount`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-53615](https://avd.aquasec.com/nvd/cve-2026-53615)

util-linux is a random collection of Linux utilities. Before util-linux 2.41.4, `parse_dos_extended()` in `libblkid/src/partitions/dos.c` computes an extended-partition start sector with 32-bit addition and does not apply the extended-area bounds checks to the first two EBR entries. A local attacker who causes a crafted DOS extended-partition disk image or removable medium to be probed can wrap `cur_start + start` to sector zero and cause libblkid to report a false partition overlapping the MBR. This directly compromises the integrity of the reported partition metadata; disk modification or availability loss requires a separate downstream consumer to act on that metadata. This issue is fixed in 2.41.4.

### CVE-2026-76642

- **Package:** `mount`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-76642](https://avd.aquasec.com/nvd/cve-2026-76642)

util-linux versions through 2.41.5 and 2.42.2 fail to check mount helper exit status before running post-mount hooks, allowing unprivileged users to execute privileged operations on pre-existing filesystems. Attackers can exploit X-mount.idmap or X-mount.owner hooks to clone filesystems with inherited suid bits or modify target inode permissions after a helper fails, achieving privilege escalation.

### CVE-2026-78408

- **Package:** `mount`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-78408](https://avd.aquasec.com/nvd/cve-2026-78408)

The nsenter --join-cgroup option opens the target cgroup.procs file as root and leaves that file descriptor open across later namespace and credential changes and across execve(). Because the kernel checks later cgroup migrations using the credentials from the original open, a program run in an attacker-controlled target can inherit root's ability to move host processes between cgroups. After a privileged operator uses --join-cgroup against that target, an unprivileged user can migrate and terminate unrelated root processes.

### CVE-2026-78409

- **Package:** `mount`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-78409](https://avd.aquasec.com/nvd/cve-2026-78409)

The X-mount.subdir option uses a detached-tree fast path on Linux 6.15 and later and passes the configured subdirectory to open_tree() with AT_SYMLINK_NOFOLLOW. That flag does not stop intermediate symlink traversal or keep resolution inside the newly mounted filesystem. A local unprivileged user with an fstab-authorized X-mount.subdir entry can attach a host path at the intended mountpoint.

### CVE-2026-78410

- **Package:** `mount`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-78410](https://avd.aquasec.com/nvd/cve-2026-78410)

A flaw was found in util-linux. Restricted bind mounts take the source path from fstab but do not pin that source before the privileged mount. A local unprivileged user who can replace the authorized source or a writable ancestor can redirect SUID mount(8) to bind another host directory. If the fstab entry also sets X-mount.owner, X-mount.group, or X-mount.mode, root then changes ownership or mode on that redirected inode.

### CVE-2025-69720

- **Package:** `ncurses-base`
- **Installed:** `6.4-4`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-69720](https://avd.aquasec.com/nvd/cve-2025-69720)

The infocmp command-line tool in ncurses before 6.5-20251213 has a stack-based buffer overflow in analyze_string in progs/infocmp.c.

### CVE-2025-69720

- **Package:** `ncurses-bin`
- **Installed:** `6.4-4`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-69720](https://avd.aquasec.com/nvd/cve-2025-69720)

The infocmp command-line tool in ncurses before 6.5-20251213 has a stack-based buffer overflow in analyze_string in progs/infocmp.c.

### CVE-2026-106553

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-106553](https://avd.aquasec.com/nvd/cve-2026-106553)

In sshd in OpenSSH before 10.6, credentials can incorrectly persist after failure of a GSSAPIAuthentication authentication attempt.

### CVE-2026-106555

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-106555](https://avd.aquasec.com/nvd/cve-2026-106555)

In sshd in OpenSSH before 10.6, GSSAPIAuthentication authentication state can incorrectly be persisted across authentication attempts.

### CVE-2026-106583

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-106583](https://avd.aquasec.com/nvd/cve-2026-106583)

In ssh in OpenSSH before 10.6, a $ or \ character can occur in a command-line username, leading to injection.

### CVE-2026-59999

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-59999](https://avd.aquasec.com/nvd/cve-2026-59999)

In sshd in OpenSSH before 10.4, DisableForwarding=yes was supposed to take precedence over PermitTunnel=yes, but did not.

### CVE-2026-60000

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-60000](https://avd.aquasec.com/nvd/cve-2026-60000)

sshd in OpenSSH before 10.4 allows remote attackers to cause a denial of service (resource consumption from excessive authentication attempts) because MaxAuthTries was mishandled for GSSAPIAuthentication.

### CVE-2026-9538

- **Package:** `perl-base`
- **Installed:** `5.36.0-7+deb12u4`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-9538](https://avd.aquasec.com/nvd/cve-2026-9538)

Archive::Tar versions before 3.10 for Perl allow memory exhaustion via attacker controlled entry size field in tar header.

_read_tar() reads each entry's payload with $handle->read($$data, $block), where $block is derived from the entry's 12-byte size field in the tar header with no upper bound on that value.

A crafted header declaring a multi-gigabyte size causes Perl to allocate a scalar of that size.

### CVE-2026-11822

- **Package:** `sqlite3`
- **Installed:** `3.40.1-2+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-11822](https://avd.aquasec.com/nvd/cve-2026-11822)

SQLite before 3.53.2 contains an out-of-bounds read vulnerability in the FTS5 full-text search extension that allows attackers to crash the process by supplying a crafted database with a malformed FTS5 leaf page. Attackers can set an oversized term length in the leaf page so that fts5LeafSeek() reads past the end of the page buffer while comparing terms during an FTS5 MATCH query, in applications compiled with SQLITE_ENABLE_FTS5.

### CVE-2026-11824

- **Package:** `sqlite3`
- **Installed:** `3.40.1-2+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-11824](https://avd.aquasec.com/nvd/cve-2026-11824)

SQLite before 3.53.2 contains a heap-based buffer overflow vulnerability in the FTS5 full-text search extension that allows attackers to cause a crash or execute arbitrary code by supplying a crafted database with malicious continuation page metadata specifying a szLeaf value smaller than 4. Attackers can trigger an integer underflow in fts5ChunkIterate() causing an inflated remaining byte count during FTS5 MATCH query processing, leading to a heap buffer overflow of attacker-controlled data in applications compiled with SQLITE_ENABLE_FTS5.

### CVE-2026-53613

- **Package:** `util-linux`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-53613](https://avd.aquasec.com/nvd/cve-2026-53613)

util-linux is a random collection of Linux utilities. In util-linux 2.17 through 2.41.6 and 2.42 through 2.42.3, and in 2.42.4 when the legacy `mount(2)` path is used without `/proc`, restricted non-root `mount` requests validate an `/etc/fstab` target before the mount operation re-resolves that pathname. A local low-privileged user authorized by an fstab `user` or `users` entry whose target has an attacker-writable ancestor can use `renameat2(RENAME_EXCHANGE)` to swap a path component and redirect an authorized mount to a root-owned location, such as mounting attacker-controlled content over `/etc/sudoers.d`, and thereby gain root privileges. Versions 2.41.5 and 2.42.2 pin targets for the new mount API, and 2.42.4 pins legacy targets through `/proc/self/fd`; the documented legacy fallback without `/proc` remains affected.

### CVE-2026-53615

- **Package:** `util-linux`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-53615](https://avd.aquasec.com/nvd/cve-2026-53615)

util-linux is a random collection of Linux utilities. Before util-linux 2.41.4, `parse_dos_extended()` in `libblkid/src/partitions/dos.c` computes an extended-partition start sector with 32-bit addition and does not apply the extended-area bounds checks to the first two EBR entries. A local attacker who causes a crafted DOS extended-partition disk image or removable medium to be probed can wrap `cur_start + start` to sector zero and cause libblkid to report a false partition overlapping the MBR. This directly compromises the integrity of the reported partition metadata; disk modification or availability loss requires a separate downstream consumer to act on that metadata. This issue is fixed in 2.41.4.

### CVE-2026-76642

- **Package:** `util-linux`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-76642](https://avd.aquasec.com/nvd/cve-2026-76642)

util-linux versions through 2.41.5 and 2.42.2 fail to check mount helper exit status before running post-mount hooks, allowing unprivileged users to execute privileged operations on pre-existing filesystems. Attackers can exploit X-mount.idmap or X-mount.owner hooks to clone filesystems with inherited suid bits or modify target inode permissions after a helper fails, achieving privilege escalation.

### CVE-2026-78408

- **Package:** `util-linux`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-78408](https://avd.aquasec.com/nvd/cve-2026-78408)

The nsenter --join-cgroup option opens the target cgroup.procs file as root and leaves that file descriptor open across later namespace and credential changes and across execve(). Because the kernel checks later cgroup migrations using the credentials from the original open, a program run in an attacker-controlled target can inherit root's ability to move host processes between cgroups. After a privileged operator uses --join-cgroup against that target, an unprivileged user can migrate and terminate unrelated root processes.

### CVE-2026-78409

- **Package:** `util-linux`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-78409](https://avd.aquasec.com/nvd/cve-2026-78409)

The X-mount.subdir option uses a detached-tree fast path on Linux 6.15 and later and passes the configured subdirectory to open_tree() with AT_SYMLINK_NOFOLLOW. That flag does not stop intermediate symlink traversal or keep resolution inside the newly mounted filesystem. A local unprivileged user with an fstab-authorized X-mount.subdir entry can attach a host path at the intended mountpoint.

### CVE-2026-78410

- **Package:** `util-linux`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-78410](https://avd.aquasec.com/nvd/cve-2026-78410)

A flaw was found in util-linux. Restricted bind mounts take the source path from fstab but do not pin that source before the privileged mount. A local unprivileged user who can replace the authorized source or a writable ancestor can redirect SUID mount(8) to bind another host directory. If the fstab entry also sets X-mount.owner, X-mount.group, or X-mount.mode, root then changes ownership or mode on that redirected inode.

### CVE-2026-53613

- **Package:** `util-linux-extra`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-53613](https://avd.aquasec.com/nvd/cve-2026-53613)

util-linux is a random collection of Linux utilities. In util-linux 2.17 through 2.41.6 and 2.42 through 2.42.3, and in 2.42.4 when the legacy `mount(2)` path is used without `/proc`, restricted non-root `mount` requests validate an `/etc/fstab` target before the mount operation re-resolves that pathname. A local low-privileged user authorized by an fstab `user` or `users` entry whose target has an attacker-writable ancestor can use `renameat2(RENAME_EXCHANGE)` to swap a path component and redirect an authorized mount to a root-owned location, such as mounting attacker-controlled content over `/etc/sudoers.d`, and thereby gain root privileges. Versions 2.41.5 and 2.42.2 pin targets for the new mount API, and 2.42.4 pins legacy targets through `/proc/self/fd`; the documented legacy fallback without `/proc` remains affected.

### CVE-2026-53615

- **Package:** `util-linux-extra`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-53615](https://avd.aquasec.com/nvd/cve-2026-53615)

util-linux is a random collection of Linux utilities. Before util-linux 2.41.4, `parse_dos_extended()` in `libblkid/src/partitions/dos.c` computes an extended-partition start sector with 32-bit addition and does not apply the extended-area bounds checks to the first two EBR entries. A local attacker who causes a crafted DOS extended-partition disk image or removable medium to be probed can wrap `cur_start + start` to sector zero and cause libblkid to report a false partition overlapping the MBR. This directly compromises the integrity of the reported partition metadata; disk modification or availability loss requires a separate downstream consumer to act on that metadata. This issue is fixed in 2.41.4.

### CVE-2026-76642

- **Package:** `util-linux-extra`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-76642](https://avd.aquasec.com/nvd/cve-2026-76642)

util-linux versions through 2.41.5 and 2.42.2 fail to check mount helper exit status before running post-mount hooks, allowing unprivileged users to execute privileged operations on pre-existing filesystems. Attackers can exploit X-mount.idmap or X-mount.owner hooks to clone filesystems with inherited suid bits or modify target inode permissions after a helper fails, achieving privilege escalation.

### CVE-2026-78408

- **Package:** `util-linux-extra`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-78408](https://avd.aquasec.com/nvd/cve-2026-78408)

The nsenter --join-cgroup option opens the target cgroup.procs file as root and leaves that file descriptor open across later namespace and credential changes and across execve(). Because the kernel checks later cgroup migrations using the credentials from the original open, a program run in an attacker-controlled target can inherit root's ability to move host processes between cgroups. After a privileged operator uses --join-cgroup against that target, an unprivileged user can migrate and terminate unrelated root processes.

### CVE-2026-78409

- **Package:** `util-linux-extra`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-78409](https://avd.aquasec.com/nvd/cve-2026-78409)

The X-mount.subdir option uses a detached-tree fast path on Linux 6.15 and later and passes the configured subdirectory to open_tree() with AT_SYMLINK_NOFOLLOW. That flag does not stop intermediate symlink traversal or keep resolution inside the newly mounted filesystem. A local unprivileged user with an fstab-authorized X-mount.subdir entry can attach a host path at the intended mountpoint.

### CVE-2026-78410

- **Package:** `util-linux-extra`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-78410](https://avd.aquasec.com/nvd/cve-2026-78410)

A flaw was found in util-linux. Restricted bind mounts take the source path from fstab but do not pin that source before the privileged mount. A local unprivileged user who can replace the authorized source or a writable ancestor can redirect SUID mount(8) to bind another host directory. If the fstab entry also sets X-mount.owner, X-mount.group, or X-mount.mode, root then changes ownership or mode on that redirected inode.

## Medium (112)

### CVE-2026-13595

- **Package:** `bsdutils`
- **Installed:** `1:2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-13595](https://avd.aquasec.com/nvd/cve-2026-13595)

A flaw was found in the libblkid library of util-linux. During nested partition probing, the BSD, Minix, Solaris x86, and UnixWare partition probers cache a raw pointer to a parent partition entry in a dynamically allocated array. When subsequent partition additions cause the array to be reallocated, this pointer becomes stale, leading to a heap use-after-free read. An attacker who can present a crafted block device image (for example, via USB insertion or a loop-mounted disk image) can trigger this flaw without user interaction, as libblkid is invoked automatically by udev/udisks as root on block-device hot-plug events. This could lead to limited information disclosure or denial of service.

### CVE-2026-27456

- **Package:** `bsdutils`
- **Installed:** `1:2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-27456](https://avd.aquasec.com/nvd/cve-2026-27456)

util-linux is a random collection of Linux utilities. Prior to version 2.41.4, a TOCTOU (Time-of-Check-Time-of-Use) vulnerability has been identified in the SUID binary /usr/bin/mount from util-linux. The mount binary, when setting up loop devices, validates the source file path with user privileges via fork() + setuid() + realpath(), but subsequently re-canonicalizes and opens it with root privileges (euid=0) without verifying that the path has not been replaced between both operations. Neither O_NOFOLLOW, nor inode comparison, nor post-open fstat() are employed. This allows a local unprivileged user to replace the source file with a symlink pointing to any root-owned file or device during the race window, causing the SUID binary to open and mount it as root. Exploitation requires an /etc/fstab entry with user,loop options whose path points to a directory where the attacker has write permission, and that /usr/bin/mount has the SUID bit set (the default configuration on virtually all Linux distributions). The impact is unauthorized read access to root-protected files and block devices, including backup images, disk volumes, and any file containing a valid filesystem. This issue has been patched in version 2.41.4.

### CVE-2026-3184

- **Package:** `bsdutils`
- **Installed:** `1:2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-3184](https://avd.aquasec.com/nvd/cve-2026-3184)

A flaw was found in util-linux. Improper hostname canonicalization in the `login(1)` utility, when invoked with the `-h` option, can modify the supplied remote hostname before setting `PAM_RHOST`. A remote attacker could exploit this by providing a specially crafted hostname, potentially bypassing host-based Pluggable Authentication Modules (PAM) access control rules that rely on fully qualified domain names. This could lead to unauthorized access.

### CVE-2026-102010

- **Package:** `gcc-12-base`
- **Installed:** `12.2.0-14+deb12u1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-102010](https://avd.aquasec.com/nvd/cve-2026-102010)

A flaw was found in GCC. When an application calls the erase_if function on a binary heap priority queue in libstdc++, the library reallocates storage but fails to update its internal entry pointer. An attacker capable of triggering this operation can exploit this use-after-free condition, leading to a Denial of Service (DoS) via an application crash or potential memory corruption.

### CVE-2026-95619

- **Package:** `gcc-12-base`
- **Installed:** `12.2.0-14+deb12u1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-95619](https://avd.aquasec.com/nvd/cve-2026-95619)

A flaw was found in libstdc++. An integer overflow can occur when processing large inputs to the aligned operator new in the C++ library. This vulnerability could lead to an undersized memory allocation, potentially causing memory corruption or application instability.

### CVE-2025-30258

- **Package:** `gpgv`
- **Installed:** `2.2.40-1.1+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-30258](https://avd.aquasec.com/nvd/cve-2025-30258)

In GnuPG before 2.5.5, if a user chooses to import a certificate with certain crafted subkey data that lacks a valid backsig or that has incorrect usage flags, the user loses the ability to verify signatures made from certain other signing keys, aka a "verification DoS."

### CVE-2025-68972

- **Package:** `gpgv`
- **Installed:** `2.2.40-1.1+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-68972](https://avd.aquasec.com/nvd/cve-2025-68972)

In GnuPG through 2.4.8, if a signed message has \f at the end of a plaintext line, an adversary can construct a modified message that places additional text after the signed material, such that signature verification of the modified message succeeds (although an "invalid armor" message is printed during verification). This is related to use of \f as a marker to denote truncation of a long plaintext line.

### CVE-2026-41991

- **Package:** `gzip`
- **Installed:** `1.12-1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-41991](https://avd.aquasec.com/nvd/cve-2026-41991)

GNU gzip contains a vulnerability in the gzexe utility related to insecure temporary file handling. When the mktemp utility is not available in the user’s PATH, gzexe falls back to constructing a temporary file path based solely on the process ID (PID). This predictable filename is created without exclusive access or existence checks.
A local attacker can pre‑create the predicted temporary file path as a symbolic link pointing to an arbitrary file writable by the victim. When gzexe runs, it follows the symlink and overwrites the target file, resulting in a time‑of‑check to time‑of‑use (TOCTOU) condition that allows arbitrary file overwrite.

This issue has been fixed in the commit 4e6f8b24ab823146ab8776f0b7fe486ab34d4269

### CVE-2026-54370

- **Package:** `libacl1`
- **Installed:** `2.3.1-3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-54370](https://avd.aquasec.com/nvd/cve-2026-54370)

acl before version 2.4.0 contains a time-of-check to time-of-use (TOCTOU) race condition vulnerability that allows local attackers to escalate privileges by replacing a pathname component with a symbolic link between an lstat() check and subsequent symlink-following operations such as stat(), chown(), chmod(), acl_get_file(), and acl_set_file(). Attackers who control a pathname component can redirect file access control list operations to arbitrary files when getfacl, setfacl, or chacl is invoked by a privileged process over an attacker-controlled path, resulting in local privilege escalation.

### CVE-2026-54371

- **Package:** `libattr1`
- **Installed:** `1:2.5.1-4`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-54371](https://avd.aquasec.com/nvd/cve-2026-54371)

attr before version 2.6.0 contains a symlink traversal vulnerability in the getfattr and setfattr utilities that allows local attackers to escalate privileges by replacing a pathname component with a symbolic link during directory hierarchy traversal. Attackers who control a pathname component can redirect getfattr and setfattr operations to arbitrary files by substituting a symlink, leading to local privilege escalation when getfattr or setfattr is invoked by a privileged process over an attacker-controlled path.

### CVE-2026-13595

- **Package:** `libblkid1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-13595](https://avd.aquasec.com/nvd/cve-2026-13595)

A flaw was found in the libblkid library of util-linux. During nested partition probing, the BSD, Minix, Solaris x86, and UnixWare partition probers cache a raw pointer to a parent partition entry in a dynamically allocated array. When subsequent partition additions cause the array to be reallocated, this pointer becomes stale, leading to a heap use-after-free read. An attacker who can present a crafted block device image (for example, via USB insertion or a loop-mounted disk image) can trigger this flaw without user interaction, as libblkid is invoked automatically by udev/udisks as root on block-device hot-plug events. This could lead to limited information disclosure or denial of service.

### CVE-2026-27456

- **Package:** `libblkid1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-27456](https://avd.aquasec.com/nvd/cve-2026-27456)

util-linux is a random collection of Linux utilities. Prior to version 2.41.4, a TOCTOU (Time-of-Check-Time-of-Use) vulnerability has been identified in the SUID binary /usr/bin/mount from util-linux. The mount binary, when setting up loop devices, validates the source file path with user privileges via fork() + setuid() + realpath(), but subsequently re-canonicalizes and opens it with root privileges (euid=0) without verifying that the path has not been replaced between both operations. Neither O_NOFOLLOW, nor inode comparison, nor post-open fstat() are employed. This allows a local unprivileged user to replace the source file with a symlink pointing to any root-owned file or device during the race window, causing the SUID binary to open and mount it as root. Exploitation requires an /etc/fstab entry with user,loop options whose path points to a directory where the attacker has write permission, and that /usr/bin/mount has the SUID bit set (the default configuration on virtually all Linux distributions). The impact is unauthorized read access to root-protected files and block devices, including backup images, disk volumes, and any file containing a valid filesystem. This issue has been patched in version 2.41.4.

### CVE-2026-3184

- **Package:** `libblkid1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-3184](https://avd.aquasec.com/nvd/cve-2026-3184)

A flaw was found in util-linux. Improper hostname canonicalization in the `login(1)` utility, when invoked with the `-h` option, can modify the supplied remote hostname before setting `PAM_RHOST`. A remote attacker could exploit this by providing a specially crafted hostname, potentially bypassing host-based Pluggable Authentication Modules (PAM) access control rules that rely on fully qualified domain names. This could lead to unauthorized access.

### CVE-2026-42250

- **Package:** `libbz2-1.0`
- **Installed:** `1.0.8-5+b1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-42250](https://avd.aquasec.com/nvd/cve-2026-42250)

bzip2 contains an off‑by‑one error in the bzip2recover utility. When processing a specially crafted file, the application performs an out‑of‑bounds write to a global buffer, resulting in memory corruption and a crash (denial of service).

This issue was fixed in bzip2 patch 35d122a3df8b0cc4082a4d89fdc6ee99f375fe67

### CVE-2026-18374

- **Package:** `libc-bin`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-18374](https://avd.aquasec.com/nvd/cve-2026-18374)

Passing an effectively empty string to the `,ccs=` syntax extension of the mode argument in the `fopen` function in the GNU C Library version 2.45 or earlier may result in a heap buffer overflow when the mode string input to the function is attacker controlled.



This usage pattern is not seen in applications in common GNU/Linux distributions and applications that process user-supplied values for `ccs` should not pass them through without validation.

### CVE-2026-19499

- **Package:** `libc-bin`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-19499](https://avd.aquasec.com/nvd/cve-2026-19499)

Calling strfmon and strfmon_l in the GNU C Library version 2.38 to 2.44 can write past the end of the caller-supplied output buffer when a conversion uses right-justified width padding.

Exploitation requires an application code path that calls strfmon or strfmon_l with right-justified width padding into a destination buffer that is large enough for the padding to succeed but too small for the internal memmove call. The field width or format may be attacker-influenced or a fixed susceptible pattern in the caller.

At the time of publication, no network-facing application impact is known.

### CVE-2026-19542

- **Package:** `libc-bin`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-19542](https://avd.aquasec.com/nvd/cve-2026-19542)

Calling tdelete on a sufficiently deep tree in the GNU C Library version 2.1 to 2.44 may write one pointer past the end of an alloca-allocated array on the stack, which may crash the application.

The tdelete implementation keeps an explicit stack of parent nodes for rebalancing, which is grown as needed while descending the tree.  Two rebalancing branches push an additional entry without checking the capacity, and write past the array when the stack is exactly full. Triggering this requires a node at a depth of exactly 40 (or 40 plus a multiple of 20), which implies a tree with at least a million nodes, so an attacker must drive a large number of insertions and deletions through an application that uses tsearch and tdelete.  The written value is a pointer into a tree node and is not directly attacker controlled.  No affected application in common distributions has been identified.

### CVE-2026-5435

- **Package:** `libc-bin`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-5435](https://avd.aquasec.com/nvd/cve-2026-5435)

The deprecated functions ns_printrrf, ns_printrr and fp_nquery in the GNU C Library version 2.2 and newer fail to enforce the caller-supplied buffer length, and can result in an out-of-bounds write when printing TSIG records.

### CVE-2026-5450

- **Package:** `libc-bin`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-5450](https://avd.aquasec.com/nvd/cve-2026-5450)

Calling the scanf family of functions with a %mc (malloc'd character match) in the GNU C Library version 2.7 to version 2.43 with a format width specifier with an explicit width greater than 1024 could result in a one byte heap buffer overflow.

### CVE-2026-5928

- **Package:** `libc-bin`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-5928](https://avd.aquasec.com/nvd/cve-2026-5928)

Calling the ungetwc function on a FILE stream with wide characters encoded in a character set that has overlaps between its single byte and multi-byte character encodings, in the GNU C Library version 2.43 or earlier, may result in an attempt to read bytes before an allocated buffer, potentially resulting in unintentional disclosure of neighboring data in the heap, or a program crash.

A bug in the wide character pushback implementation (_IO_wdefault_pbackfail in libio/wgenops.c) causes ungetwc() to operate on the regular character buffer (fp->_IO_read_ptr) instead of the actual wide-stream read pointer (fp->_wide_data->_IO_read_ptr). The program crash may happen in cases where fp->_IO_read_ptr is not initialized and hence points to NULL. The buffer under-read requires a special situation where the input character encoding is such that there are overlaps between single byte representations and multibyte representations in that encoding, resulting in spurious matches. The spurious match case is not possible in the standard Unicode character sets.

### CVE-2026-6238

- **Package:** `libc-bin`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-6238](https://avd.aquasec.com/nvd/cve-2026-6238)

The deprecated functions ns_printrrf, ns_printrr and fp_nquery in the GNU C Library version 2.0.1 to version 2.43 fail to validate the RDATA content against the RDATA length in a DNS response when processing A6, CERT, LOC, TKEY or TSIG records, which may allow an attacker to craft a DNS response, causing a target application to crash or read uninitialized memory.

These functions are for application debugging only and hence not in the path of code executed by the DNS resolver.  Further, they have been deprecated since version 2.34 and should not be used by any new applications.  Applications should consider porting away from these interfaces since they may be removed in future versions.

### CVE-2026-6368

- **Package:** `libc-bin`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-6368](https://avd.aquasec.com/nvd/cve-2026-6368)

Calling wordexp with WRDE_APPEND in the GNU C Library version 2.0 to version 2.43 can cause the interface to return invalid memory in the we_wordv member, which on subsequent calls to wordfree may abort the process.

### CVE-2026-6791

- **Package:** `libc-bin`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-6791](https://avd.aquasec.com/nvd/cve-2026-6791)

When expanding paths that begin with a tilde (~) followed by a username, the internal parse_tilde function extracts the username to determine the user's home directory.  The implementation allocates memory for this username directly on the stack using the strndupa macro. Because the size of this allocation was determined by the length of the user-supplied input without any bounds checks, passing an excessively long username e.g. thousands of characters, forces the thread to exhaust its stack space. Thus if an application passes untrusted, attacker-controlled input to the wordexp function, an attacker can trigger a stack clash.

### CVE-2026-77117

- **Package:** `libc-bin`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-77117](https://avd.aquasec.com/nvd/cve-2026-77117)

Converting crafted SHIFT_JISX0213 input to UCS-4 or the internal wide character encoding, for example with iconv, in the GNU C Library version 2.3 to 2.44 may result in the converter making no progress, causing the calling application to hang.

Some SHIFT_JISX0213 sequences decode to two code points.  If the output buffer has room for only the first one, the converter stores the second in the conversion state and returns E2BIG, but it never clears that pending character after emitting it on the next call.  The converter then keeps emitting the pending character without consuming further input, so an application that retries the conversion loops forever. The input must be attacker controlled and the application must convert it with an output buffer small enough to split the two code points. Only the SHIFT_JISX0213 character set is affected, which is not commonly used.  The related defect in the EUC_JISX0213 converter is tracked separately as CVE-2026-80489.

### CVE-2026-80489

- **Package:** `libc-bin`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-80489](https://avd.aquasec.com/nvd/cve-2026-80489)

Converting crafted EUC_JISX0213 input to UCS-4 or the internal wide character encoding, for example with iconv, in the GNU C Library version 2.3 to 2.44 may result in the converter making no progress, causing the calling application to hang.

Some EUC_JISX0213 sequences decode to two code points.  If the output buffer has room for only the first one, the converter stores the second in the conversion state and returns E2BIG, but it never clears that pending character after emitting it on the next call.  The converter then keeps emitting the pending character without consuming further input, so an application that retries the conversion loops forever. The input must be attacker controlled and the application must convert it with an output buffer small enough to split the two code points. Only the EUC_JISX0213 character set is affected, which is not commonly used.  The related defect in SHIFT_JISX0213 converter is tracked separately as CVE-2026-77117.

### CVE-2026-8674

- **Package:** `libc-bin`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-8674](https://avd.aquasec.com/nvd/cve-2026-8674)

Initializing the DNS stub resolver from an /etc/resolv.conf file, or a LOCALDOMAIN environment variable, whose search list contains a domain of roughly 200 characters or more in the GNU C Library version 2.26 to 2.44 results in an assertion failure which aborts the process.

The resolver truncates the search list when copying it into the fixed-size _res.defdname buffer, then asserts that the copy is consistent with the full configuration.  The consistency check compared against the wrong size and did not handle a first entry that does not fit, so a correctly truncated list failed the assertion.  Any process that resolves names through the library is affected, including long-running processes that reload /etc/resolv.conf on the next query after it changes.  Search domains are commonly written to /etc/resolv.conf from data received over DHCP or from a VPN server, so an attacker on the local network may be able to trigger this without privileges on the target system, subject to validation by the network configuration software.

### CVE-2026-86805

- **Package:** `libc-bin`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-86805](https://avd.aquasec.com/nvd/cve-2026-86805)

A time-of-check to time-of-use (TOCTOU) race condition in the dynamic loader (ld.so) of the GNU C Library (glibc) versions 2.14 through 2.44 allows a local attacker to escalate privileges. When expanding $ORIGIN in DT_RPATH for setuid/setgid (AT_SECURE) programs, glibc validates the lexically normalized search path against the trusted directories but then opens the raw, un-normalized path. On systems where the Linux fs.protected_hardlinks sysctl is disabled, a local attacker who hard-links such a program into an attacker-controlled directory and wins a race to replace an intermediate path component with a symbolic link can direct the loader outside the trusted directory, causing it to load an attacker-controlled shared object and execute arbitrary code with the elevated privileges of the program.

Exploitation requires an installed setuid or setgid binary whose DT_RPATH uses $ORIGIN followed by ".." traversal that normalizes into a trusted directory, and the ability to hard-link that binary and win the race by swapping a path component for a symbolic link. Major Linux-based OS distributions ship with fs.protected_hardlinks enabled by default and mitigate the vulnerability.

### CVE-2026-89092

- **Package:** `libc-bin`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-89092](https://avd.aquasec.com/nvd/cve-2026-89092)

The nscd service in the GNU C Library 2.3.4 onwards may crash due to a 
stack overflow when a malicious DNS server returns too large a response 
for a DNS query, resulting in degraded DNS resolution for the system.



Exploitation of this bug needs a system that has nscd enabled and using 
an untrusted DNS server for name resolution, with the compromised DNS 
server being capable of processing records large enough to result in a 
stack overflow in an nscd thread stack.  During experimentation, bind 9 
was unable to handle large records, but that could change in future or 
with a different name server.  In typical installations, nscd is 
executed in an isolated context as its own user without a shell, due to 
which any compromise of that service is isolated.



There is a remote possibility of nscd cache corruption if an attacker 
manages to get the stack pointer into a desired point in the heap, 
potentially resulting in other caches in nscd being overwritten with 
corrupt data through the stack overflow, until the buggy code path 
eventually results in a crash.



Finally, a crash in nscd may result in performance degradation when 
resolving names, but it does not result in a denial of service.

### CVE-2026-95818

- **Package:** `libc-bin`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-95818](https://avd.aquasec.com/nvd/cve-2026-95818)

A stack-based buffer overflow in the dynamic loader (ld.so) of the GNU C Library (glibc) versions 2.14 through 2.44 allows a local attacker to crash or corrupt the memory of setuid/setgid (AT_SECURE) programs.

When such a program's DT_RPATH or DT_RUNPATH begins with $ORIGIN and is followed by NUL or '/' the loader both reads past the end of the path buffer and writes past the end of a stack-allocated internal buffer. The corrupted loader stack can lead to a loader crash (denial of service) and limited disclosure of process memory.

### CVE-2026-18374

- **Package:** `libc6`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-18374](https://avd.aquasec.com/nvd/cve-2026-18374)

Passing an effectively empty string to the `,ccs=` syntax extension of the mode argument in the `fopen` function in the GNU C Library version 2.45 or earlier may result in a heap buffer overflow when the mode string input to the function is attacker controlled.



This usage pattern is not seen in applications in common GNU/Linux distributions and applications that process user-supplied values for `ccs` should not pass them through without validation.

### CVE-2026-19499

- **Package:** `libc6`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-19499](https://avd.aquasec.com/nvd/cve-2026-19499)

Calling strfmon and strfmon_l in the GNU C Library version 2.38 to 2.44 can write past the end of the caller-supplied output buffer when a conversion uses right-justified width padding.

Exploitation requires an application code path that calls strfmon or strfmon_l with right-justified width padding into a destination buffer that is large enough for the padding to succeed but too small for the internal memmove call. The field width or format may be attacker-influenced or a fixed susceptible pattern in the caller.

At the time of publication, no network-facing application impact is known.

### CVE-2026-19542

- **Package:** `libc6`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-19542](https://avd.aquasec.com/nvd/cve-2026-19542)

Calling tdelete on a sufficiently deep tree in the GNU C Library version 2.1 to 2.44 may write one pointer past the end of an alloca-allocated array on the stack, which may crash the application.

The tdelete implementation keeps an explicit stack of parent nodes for rebalancing, which is grown as needed while descending the tree.  Two rebalancing branches push an additional entry without checking the capacity, and write past the array when the stack is exactly full. Triggering this requires a node at a depth of exactly 40 (or 40 plus a multiple of 20), which implies a tree with at least a million nodes, so an attacker must drive a large number of insertions and deletions through an application that uses tsearch and tdelete.  The written value is a pointer into a tree node and is not directly attacker controlled.  No affected application in common distributions has been identified.

### CVE-2026-5435

- **Package:** `libc6`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-5435](https://avd.aquasec.com/nvd/cve-2026-5435)

The deprecated functions ns_printrrf, ns_printrr and fp_nquery in the GNU C Library version 2.2 and newer fail to enforce the caller-supplied buffer length, and can result in an out-of-bounds write when printing TSIG records.

### CVE-2026-5450

- **Package:** `libc6`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-5450](https://avd.aquasec.com/nvd/cve-2026-5450)

Calling the scanf family of functions with a %mc (malloc'd character match) in the GNU C Library version 2.7 to version 2.43 with a format width specifier with an explicit width greater than 1024 could result in a one byte heap buffer overflow.

### CVE-2026-5928

- **Package:** `libc6`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-5928](https://avd.aquasec.com/nvd/cve-2026-5928)

Calling the ungetwc function on a FILE stream with wide characters encoded in a character set that has overlaps between its single byte and multi-byte character encodings, in the GNU C Library version 2.43 or earlier, may result in an attempt to read bytes before an allocated buffer, potentially resulting in unintentional disclosure of neighboring data in the heap, or a program crash.

A bug in the wide character pushback implementation (_IO_wdefault_pbackfail in libio/wgenops.c) causes ungetwc() to operate on the regular character buffer (fp->_IO_read_ptr) instead of the actual wide-stream read pointer (fp->_wide_data->_IO_read_ptr). The program crash may happen in cases where fp->_IO_read_ptr is not initialized and hence points to NULL. The buffer under-read requires a special situation where the input character encoding is such that there are overlaps between single byte representations and multibyte representations in that encoding, resulting in spurious matches. The spurious match case is not possible in the standard Unicode character sets.

### CVE-2026-6238

- **Package:** `libc6`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-6238](https://avd.aquasec.com/nvd/cve-2026-6238)

The deprecated functions ns_printrrf, ns_printrr and fp_nquery in the GNU C Library version 2.0.1 to version 2.43 fail to validate the RDATA content against the RDATA length in a DNS response when processing A6, CERT, LOC, TKEY or TSIG records, which may allow an attacker to craft a DNS response, causing a target application to crash or read uninitialized memory.

These functions are for application debugging only and hence not in the path of code executed by the DNS resolver.  Further, they have been deprecated since version 2.34 and should not be used by any new applications.  Applications should consider porting away from these interfaces since they may be removed in future versions.

### CVE-2026-6368

- **Package:** `libc6`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-6368](https://avd.aquasec.com/nvd/cve-2026-6368)

Calling wordexp with WRDE_APPEND in the GNU C Library version 2.0 to version 2.43 can cause the interface to return invalid memory in the we_wordv member, which on subsequent calls to wordfree may abort the process.

### CVE-2026-6791

- **Package:** `libc6`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-6791](https://avd.aquasec.com/nvd/cve-2026-6791)

When expanding paths that begin with a tilde (~) followed by a username, the internal parse_tilde function extracts the username to determine the user's home directory.  The implementation allocates memory for this username directly on the stack using the strndupa macro. Because the size of this allocation was determined by the length of the user-supplied input without any bounds checks, passing an excessively long username e.g. thousands of characters, forces the thread to exhaust its stack space. Thus if an application passes untrusted, attacker-controlled input to the wordexp function, an attacker can trigger a stack clash.

### CVE-2026-77117

- **Package:** `libc6`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-77117](https://avd.aquasec.com/nvd/cve-2026-77117)

Converting crafted SHIFT_JISX0213 input to UCS-4 or the internal wide character encoding, for example with iconv, in the GNU C Library version 2.3 to 2.44 may result in the converter making no progress, causing the calling application to hang.

Some SHIFT_JISX0213 sequences decode to two code points.  If the output buffer has room for only the first one, the converter stores the second in the conversion state and returns E2BIG, but it never clears that pending character after emitting it on the next call.  The converter then keeps emitting the pending character without consuming further input, so an application that retries the conversion loops forever. The input must be attacker controlled and the application must convert it with an output buffer small enough to split the two code points. Only the SHIFT_JISX0213 character set is affected, which is not commonly used.  The related defect in the EUC_JISX0213 converter is tracked separately as CVE-2026-80489.

### CVE-2026-80489

- **Package:** `libc6`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-80489](https://avd.aquasec.com/nvd/cve-2026-80489)

Converting crafted EUC_JISX0213 input to UCS-4 or the internal wide character encoding, for example with iconv, in the GNU C Library version 2.3 to 2.44 may result in the converter making no progress, causing the calling application to hang.

Some EUC_JISX0213 sequences decode to two code points.  If the output buffer has room for only the first one, the converter stores the second in the conversion state and returns E2BIG, but it never clears that pending character after emitting it on the next call.  The converter then keeps emitting the pending character without consuming further input, so an application that retries the conversion loops forever. The input must be attacker controlled and the application must convert it with an output buffer small enough to split the two code points. Only the EUC_JISX0213 character set is affected, which is not commonly used.  The related defect in SHIFT_JISX0213 converter is tracked separately as CVE-2026-77117.

### CVE-2026-8674

- **Package:** `libc6`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-8674](https://avd.aquasec.com/nvd/cve-2026-8674)

Initializing the DNS stub resolver from an /etc/resolv.conf file, or a LOCALDOMAIN environment variable, whose search list contains a domain of roughly 200 characters or more in the GNU C Library version 2.26 to 2.44 results in an assertion failure which aborts the process.

The resolver truncates the search list when copying it into the fixed-size _res.defdname buffer, then asserts that the copy is consistent with the full configuration.  The consistency check compared against the wrong size and did not handle a first entry that does not fit, so a correctly truncated list failed the assertion.  Any process that resolves names through the library is affected, including long-running processes that reload /etc/resolv.conf on the next query after it changes.  Search domains are commonly written to /etc/resolv.conf from data received over DHCP or from a VPN server, so an attacker on the local network may be able to trigger this without privileges on the target system, subject to validation by the network configuration software.

### CVE-2026-86805

- **Package:** `libc6`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-86805](https://avd.aquasec.com/nvd/cve-2026-86805)

A time-of-check to time-of-use (TOCTOU) race condition in the dynamic loader (ld.so) of the GNU C Library (glibc) versions 2.14 through 2.44 allows a local attacker to escalate privileges. When expanding $ORIGIN in DT_RPATH for setuid/setgid (AT_SECURE) programs, glibc validates the lexically normalized search path against the trusted directories but then opens the raw, un-normalized path. On systems where the Linux fs.protected_hardlinks sysctl is disabled, a local attacker who hard-links such a program into an attacker-controlled directory and wins a race to replace an intermediate path component with a symbolic link can direct the loader outside the trusted directory, causing it to load an attacker-controlled shared object and execute arbitrary code with the elevated privileges of the program.

Exploitation requires an installed setuid or setgid binary whose DT_RPATH uses $ORIGIN followed by ".." traversal that normalizes into a trusted directory, and the ability to hard-link that binary and win the race by swapping a path component for a symbolic link. Major Linux-based OS distributions ship with fs.protected_hardlinks enabled by default and mitigate the vulnerability.

### CVE-2026-89092

- **Package:** `libc6`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-89092](https://avd.aquasec.com/nvd/cve-2026-89092)

The nscd service in the GNU C Library 2.3.4 onwards may crash due to a 
stack overflow when a malicious DNS server returns too large a response 
for a DNS query, resulting in degraded DNS resolution for the system.



Exploitation of this bug needs a system that has nscd enabled and using 
an untrusted DNS server for name resolution, with the compromised DNS 
server being capable of processing records large enough to result in a 
stack overflow in an nscd thread stack.  During experimentation, bind 9 
was unable to handle large records, but that could change in future or 
with a different name server.  In typical installations, nscd is 
executed in an isolated context as its own user without a shell, due to 
which any compromise of that service is isolated.



There is a remote possibility of nscd cache corruption if an attacker 
manages to get the stack pointer into a desired point in the heap, 
potentially resulting in other caches in nscd being overwritten with 
corrupt data through the stack overflow, until the buggy code path 
eventually results in a crash.



Finally, a crash in nscd may result in performance degradation when 
resolving names, but it does not result in a denial of service.

### CVE-2026-95818

- **Package:** `libc6`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-95818](https://avd.aquasec.com/nvd/cve-2026-95818)

A stack-based buffer overflow in the dynamic loader (ld.so) of the GNU C Library (glibc) versions 2.14 through 2.44 allows a local attacker to crash or corrupt the memory of setuid/setgid (AT_SECURE) programs.

When such a program's DT_RPATH or DT_RUNPATH begins with $ORIGIN and is followed by NUL or '/' the loader both reads past the end of the path buffer and writes past the end of a stack-allocated internal buffer. The corrupted loader stack can lead to a loader crash (denial of service) and limited disclosure of process memory.

### CVE-2026-102010

- **Package:** `libgcc-s1`
- **Installed:** `12.2.0-14+deb12u1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-102010](https://avd.aquasec.com/nvd/cve-2026-102010)

A flaw was found in GCC. When an application calls the erase_if function on a binary heap priority queue in libstdc++, the library reallocates storage but fails to update its internal entry pointer. An attacker capable of triggering this operation can exploit this use-after-free condition, leading to a Denial of Service (DoS) via an application crash or potential memory corruption.

### CVE-2026-95619

- **Package:** `libgcc-s1`
- **Installed:** `12.2.0-14+deb12u1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-95619](https://avd.aquasec.com/nvd/cve-2026-95619)

A flaw was found in libstdc++. An integer overflow can occur when processing large inputs to the aligned operator new in the C++ library. This vulnerability could lead to an undersized memory allocation, potentially causing memory corruption or application instability.

### CVE-2026-107708

- **Package:** `libgssapi-krb5-2`
- **Installed:** `1.20.1-2+deb12u5`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-107708](https://avd.aquasec.com/nvd/cve-2026-107708)

MIT krb5 through 1.22.2 contains a NULL pointer dereference vulnerability in the KDC's get_pac_princ_with_realm() that returns success while leaving the client principal NULL on malformed names. A malicious or compromised cross-realm trusted KDC can send an S4U2Proxy request with a PAC carrying a malformed client name to crash krb5kdc and deny authentication.

### CVE-2026-107778

- **Package:** `libgssapi-krb5-2`
- **Installed:** `1.20.1-2+deb12u5`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-107778](https://avd.aquasec.com/nvd/cve-2026-107778)

MIT Kerberos 5 (krb5) through 1.22.2 contains a NULL pointer dereference in make_cred_list() in rd_cred.c that allows authenticated Kerberos clients to crash services by sending mismatched KRB-CRED arrays. Attackers can send forwarded credentials with more tickets than ticket_info entries through gss_accept_sec_context() to crash GSS-API acceptor services, causing denial of service.

### CVE-2026-107708

- **Package:** `libk5crypto3`
- **Installed:** `1.20.1-2+deb12u5`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-107708](https://avd.aquasec.com/nvd/cve-2026-107708)

MIT krb5 through 1.22.2 contains a NULL pointer dereference vulnerability in the KDC's get_pac_princ_with_realm() that returns success while leaving the client principal NULL on malformed names. A malicious or compromised cross-realm trusted KDC can send an S4U2Proxy request with a PAC carrying a malformed client name to crash krb5kdc and deny authentication.

### CVE-2026-107778

- **Package:** `libk5crypto3`
- **Installed:** `1.20.1-2+deb12u5`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-107778](https://avd.aquasec.com/nvd/cve-2026-107778)

MIT Kerberos 5 (krb5) through 1.22.2 contains a NULL pointer dereference in make_cred_list() in rd_cred.c that allows authenticated Kerberos clients to crash services by sending mismatched KRB-CRED arrays. Attackers can send forwarded credentials with more tickets than ticket_info entries through gss_accept_sec_context() to crash GSS-API acceptor services, causing denial of service.

### CVE-2026-107708

- **Package:** `libkrb5-3`
- **Installed:** `1.20.1-2+deb12u5`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-107708](https://avd.aquasec.com/nvd/cve-2026-107708)

MIT krb5 through 1.22.2 contains a NULL pointer dereference vulnerability in the KDC's get_pac_princ_with_realm() that returns success while leaving the client principal NULL on malformed names. A malicious or compromised cross-realm trusted KDC can send an S4U2Proxy request with a PAC carrying a malformed client name to crash krb5kdc and deny authentication.

### CVE-2026-107778

- **Package:** `libkrb5-3`
- **Installed:** `1.20.1-2+deb12u5`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-107778](https://avd.aquasec.com/nvd/cve-2026-107778)

MIT Kerberos 5 (krb5) through 1.22.2 contains a NULL pointer dereference in make_cred_list() in rd_cred.c that allows authenticated Kerberos clients to crash services by sending mismatched KRB-CRED arrays. Attackers can send forwarded credentials with more tickets than ticket_info entries through gss_accept_sec_context() to crash GSS-API acceptor services, causing denial of service.

### CVE-2026-107708

- **Package:** `libkrb5support0`
- **Installed:** `1.20.1-2+deb12u5`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-107708](https://avd.aquasec.com/nvd/cve-2026-107708)

MIT krb5 through 1.22.2 contains a NULL pointer dereference vulnerability in the KDC's get_pac_princ_with_realm() that returns success while leaving the client principal NULL on malformed names. A malicious or compromised cross-realm trusted KDC can send an S4U2Proxy request with a PAC carrying a malformed client name to crash krb5kdc and deny authentication.

### CVE-2026-107778

- **Package:** `libkrb5support0`
- **Installed:** `1.20.1-2+deb12u5`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-107778](https://avd.aquasec.com/nvd/cve-2026-107778)

MIT Kerberos 5 (krb5) through 1.22.2 contains a NULL pointer dereference in make_cred_list() in rd_cred.c that allows authenticated Kerberos clients to crash services by sending mismatched KRB-CRED arrays. Attackers can send forwarded credentials with more tickets than ticket_info entries through gss_accept_sec_context() to crash GSS-API acceptor services, causing denial of service.

### CVE-2026-13595

- **Package:** `libmount1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-13595](https://avd.aquasec.com/nvd/cve-2026-13595)

A flaw was found in the libblkid library of util-linux. During nested partition probing, the BSD, Minix, Solaris x86, and UnixWare partition probers cache a raw pointer to a parent partition entry in a dynamically allocated array. When subsequent partition additions cause the array to be reallocated, this pointer becomes stale, leading to a heap use-after-free read. An attacker who can present a crafted block device image (for example, via USB insertion or a loop-mounted disk image) can trigger this flaw without user interaction, as libblkid is invoked automatically by udev/udisks as root on block-device hot-plug events. This could lead to limited information disclosure or denial of service.

### CVE-2026-27456

- **Package:** `libmount1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-27456](https://avd.aquasec.com/nvd/cve-2026-27456)

util-linux is a random collection of Linux utilities. Prior to version 2.41.4, a TOCTOU (Time-of-Check-Time-of-Use) vulnerability has been identified in the SUID binary /usr/bin/mount from util-linux. The mount binary, when setting up loop devices, validates the source file path with user privileges via fork() + setuid() + realpath(), but subsequently re-canonicalizes and opens it with root privileges (euid=0) without verifying that the path has not been replaced between both operations. Neither O_NOFOLLOW, nor inode comparison, nor post-open fstat() are employed. This allows a local unprivileged user to replace the source file with a symlink pointing to any root-owned file or device during the race window, causing the SUID binary to open and mount it as root. Exploitation requires an /etc/fstab entry with user,loop options whose path points to a directory where the attacker has write permission, and that /usr/bin/mount has the SUID bit set (the default configuration on virtually all Linux distributions). The impact is unauthorized read access to root-protected files and block devices, including backup images, disk volumes, and any file containing a valid filesystem. This issue has been patched in version 2.41.4.

### CVE-2026-3184

- **Package:** `libmount1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-3184](https://avd.aquasec.com/nvd/cve-2026-3184)

A flaw was found in util-linux. Improper hostname canonicalization in the `login(1)` utility, when invoked with the `-h` option, can modify the supplied remote hostname before setting `PAM_RHOST`. A remote attacker could exploit this by providing a specially crafted hostname, potentially bypassing host-based Pluggable Authentication Modules (PAM) access control rules that rely on fully qualified domain names. This could lead to unauthorized access.

### CVE-2023-50495

- **Package:** `libncursesw6`
- **Installed:** `6.4-4`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2023-50495](https://avd.aquasec.com/nvd/cve-2023-50495)

NCurse v6.4-20230418 was discovered to contain a segmentation fault via the component _nc_wrap_entry().

### CVE-2026-13757

- **Package:** `libp11-kit0`
- **Installed:** `0.24.1-2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-13757](https://avd.aquasec.com/nvd/cve-2026-13757)

A flaw was found in p11-kit. The RPC message attribute parsing functions p11_rpc_message_get_attribute() and p11_rpc_message_get_attribute_array_value() form a mutually-recursive call chain with no recursion depth limit when processing nested CKA_WRAP_TEMPLATE, CKA_UNWRAP_TEMPLATE, and CKA_DERIVE_TEMPLATE attributes. An unauthenticated attacker with local access to the p11-kit RPC Unix domain socket can send a specially crafted request with deeply nested template attributes, causing stack exhaustion and crashing the p11-kit server process and its dependent services.

### CVE-2026-18938

- **Package:** `libp11-kit0`
- **Installed:** `0.24.1-2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-18938](https://avd.aquasec.com/nvd/cve-2026-18938)

A flaw was found in p11-kit. A local attacker, or one with equivalent access to a reachable RPC channel, could exploit an integer overflow vulnerability. By sending specially crafted messages, the attacker can cause the system to miscalculate memory allocation for nested attributes. This leads to a memory corruption issue, specifically a heap out-of-bounds write, which can crash the p11-kit RPC parsing process, resulting in a Denial of Service (DoS). This vulnerability is only exploitable on 32 bit systems.

### CVE-2024-10041

- **Package:** `libpam-modules`
- **Installed:** `1.5.2-6+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2024-10041](https://avd.aquasec.com/nvd/cve-2024-10041)

A vulnerability was found in PAM. The secret information is stored in memory, where the attacker can trigger the victim program to execute by sending characters to its standard input (stdin). As this occurs, the attacker can train the branch predictor to execute an ROP chain speculatively. This flaw could result in leaked passwords, such as those found in /etc/shadow while performing authentications.

### CVE-2026-54411

- **Package:** `libpam-modules`
- **Installed:** `1.5.2-6+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-54411](https://avd.aquasec.com/nvd/cve-2026-54411)

Linux-PAM through 1.7.2 contains an observable timing discrepancy (CWE-208) in the pam_userdb module's plaintext-password comparison path in modules/pam_userdb/pam_userdb.c that allows a local or network-adjacent attacker able to repeatedly drive authentication through a calling service to recover the plaintext password of a target account by measuring response-timing differences.

### CVE-2024-10041

- **Package:** `libpam-modules-bin`
- **Installed:** `1.5.2-6+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2024-10041](https://avd.aquasec.com/nvd/cve-2024-10041)

A vulnerability was found in PAM. The secret information is stored in memory, where the attacker can trigger the victim program to execute by sending characters to its standard input (stdin). As this occurs, the attacker can train the branch predictor to execute an ROP chain speculatively. This flaw could result in leaked passwords, such as those found in /etc/shadow while performing authentications.

### CVE-2026-54411

- **Package:** `libpam-modules-bin`
- **Installed:** `1.5.2-6+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-54411](https://avd.aquasec.com/nvd/cve-2026-54411)

Linux-PAM through 1.7.2 contains an observable timing discrepancy (CWE-208) in the pam_userdb module's plaintext-password comparison path in modules/pam_userdb/pam_userdb.c that allows a local or network-adjacent attacker able to repeatedly drive authentication through a calling service to recover the plaintext password of a target account by measuring response-timing differences.

### CVE-2024-10041

- **Package:** `libpam-runtime`
- **Installed:** `1.5.2-6+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2024-10041](https://avd.aquasec.com/nvd/cve-2024-10041)

A vulnerability was found in PAM. The secret information is stored in memory, where the attacker can trigger the victim program to execute by sending characters to its standard input (stdin). As this occurs, the attacker can train the branch predictor to execute an ROP chain speculatively. This flaw could result in leaked passwords, such as those found in /etc/shadow while performing authentications.

### CVE-2026-54411

- **Package:** `libpam-runtime`
- **Installed:** `1.5.2-6+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-54411](https://avd.aquasec.com/nvd/cve-2026-54411)

Linux-PAM through 1.7.2 contains an observable timing discrepancy (CWE-208) in the pam_userdb module's plaintext-password comparison path in modules/pam_userdb/pam_userdb.c that allows a local or network-adjacent attacker able to repeatedly drive authentication through a calling service to recover the plaintext password of a target account by measuring response-timing differences.

### CVE-2024-10041

- **Package:** `libpam0g`
- **Installed:** `1.5.2-6+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2024-10041](https://avd.aquasec.com/nvd/cve-2024-10041)

A vulnerability was found in PAM. The secret information is stored in memory, where the attacker can trigger the victim program to execute by sending characters to its standard input (stdin). As this occurs, the attacker can train the branch predictor to execute an ROP chain speculatively. This flaw could result in leaked passwords, such as those found in /etc/shadow while performing authentications.

### CVE-2026-54411

- **Package:** `libpam0g`
- **Installed:** `1.5.2-6+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-54411](https://avd.aquasec.com/nvd/cve-2026-54411)

Linux-PAM through 1.7.2 contains an observable timing discrepancy (CWE-208) in the pam_userdb module's plaintext-password comparison path in modules/pam_userdb/pam_userdb.c that allows a local or network-adjacent attacker able to repeatedly drive authentication through a calling service to recover the plaintext password of a target account by measuring response-timing differences.

### CVE-2026-13595

- **Package:** `libsmartcols1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-13595](https://avd.aquasec.com/nvd/cve-2026-13595)

A flaw was found in the libblkid library of util-linux. During nested partition probing, the BSD, Minix, Solaris x86, and UnixWare partition probers cache a raw pointer to a parent partition entry in a dynamically allocated array. When subsequent partition additions cause the array to be reallocated, this pointer becomes stale, leading to a heap use-after-free read. An attacker who can present a crafted block device image (for example, via USB insertion or a loop-mounted disk image) can trigger this flaw without user interaction, as libblkid is invoked automatically by udev/udisks as root on block-device hot-plug events. This could lead to limited information disclosure or denial of service.

### CVE-2026-27456

- **Package:** `libsmartcols1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-27456](https://avd.aquasec.com/nvd/cve-2026-27456)

util-linux is a random collection of Linux utilities. Prior to version 2.41.4, a TOCTOU (Time-of-Check-Time-of-Use) vulnerability has been identified in the SUID binary /usr/bin/mount from util-linux. The mount binary, when setting up loop devices, validates the source file path with user privileges via fork() + setuid() + realpath(), but subsequently re-canonicalizes and opens it with root privileges (euid=0) without verifying that the path has not been replaced between both operations. Neither O_NOFOLLOW, nor inode comparison, nor post-open fstat() are employed. This allows a local unprivileged user to replace the source file with a symlink pointing to any root-owned file or device during the race window, causing the SUID binary to open and mount it as root. Exploitation requires an /etc/fstab entry with user,loop options whose path points to a directory where the attacker has write permission, and that /usr/bin/mount has the SUID bit set (the default configuration on virtually all Linux distributions). The impact is unauthorized read access to root-protected files and block devices, including backup images, disk volumes, and any file containing a valid filesystem. This issue has been patched in version 2.41.4.

### CVE-2026-3184

- **Package:** `libsmartcols1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-3184](https://avd.aquasec.com/nvd/cve-2026-3184)

A flaw was found in util-linux. Improper hostname canonicalization in the `login(1)` utility, when invoked with the `-h` option, can modify the supplied remote hostname before setting `PAM_RHOST`. A remote attacker could exploit this by providing a specially crafted hostname, potentially bypassing host-based Pluggable Authentication Modules (PAM) access control rules that rely on fully qualified domain names. This could lead to unauthorized access.

### CVE-2025-7709

- **Package:** `libsqlite3-0`
- **Installed:** `3.40.1-2+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-7709](https://avd.aquasec.com/nvd/cve-2025-7709)

An integer overflow exists in the  FTS5 https://sqlite.org/fts5.html  extension. It occurs when the size of an array of tombstone pointers is calculated and truncated into a 32-bit integer. A pointer to partially controlled data can then be written out of bounds.

### CVE-2026-50812

- **Package:** `libsqlite3-0`
- **Installed:** `3.40.1-2+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-50812](https://avd.aquasec.com/nvd/cve-2026-50812)

A NULL pointer dereference in the SQLite Session Extension in SQLite 3.53.1 and SQLite trunk builds before check-in e807d4e3798efd53 allows an attacker who can supply a malformed changeset blob to cause a denial of service. The issue occurs when sqlite3changeset_apply_v3() applies a corrupt changeset and reaches sqlite3_value_type() with a NULL sqlite3_value pointer.

### CVE-2026-50813

- **Package:** `libsqlite3-0`
- **Installed:** `3.40.1-2+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-50813](https://avd.aquasec.com/nvd/cve-2026-50813)

An issue in SQLite before Fossil check-in 869a51ae84df allows a local attacker to obtain sensitive information via the Session Extension changeset concat/changegroup merge path

### CVE-2026-102010

- **Package:** `libstdc++6`
- **Installed:** `12.2.0-14+deb12u1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-102010](https://avd.aquasec.com/nvd/cve-2026-102010)

A flaw was found in GCC. When an application calls the erase_if function on a binary heap priority queue in libstdc++, the library reallocates storage but fails to update its internal entry pointer. An attacker capable of triggering this operation can exploit this use-after-free condition, leading to a Denial of Service (DoS) via an application crash or potential memory corruption.

### CVE-2026-95619

- **Package:** `libstdc++6`
- **Installed:** `12.2.0-14+deb12u1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-95619](https://avd.aquasec.com/nvd/cve-2026-95619)

A flaw was found in libstdc++. An integer overflow can occur when processing large inputs to the aligned operator new in the C++ library. This vulnerability could lead to an undersized memory allocation, potentially causing memory corruption or application instability.

### CVE-2026-15059

- **Package:** `libsystemd0`
- **Installed:** `252.39-1~deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-15059](https://avd.aquasec.com/nvd/cve-2026-15059)

Local unprivileged users can terminate arbitrary local processes via a systemd-oomd IPC API due to a missing path traversal validation.

### CVE-2023-50495

- **Package:** `libtinfo6`
- **Installed:** `6.4-4`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2023-50495](https://avd.aquasec.com/nvd/cve-2023-50495)

NCurse v6.4-20230418 was discovered to contain a segmentation fault via the component _nc_wrap_entry().

### CVE-2026-15059

- **Package:** `libudev1`
- **Installed:** `252.39-1~deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-15059](https://avd.aquasec.com/nvd/cve-2026-15059)

Local unprivileged users can terminate arbitrary local processes via a systemd-oomd IPC API due to a missing path traversal validation.

### CVE-2026-13595

- **Package:** `libuuid1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-13595](https://avd.aquasec.com/nvd/cve-2026-13595)

A flaw was found in the libblkid library of util-linux. During nested partition probing, the BSD, Minix, Solaris x86, and UnixWare partition probers cache a raw pointer to a parent partition entry in a dynamically allocated array. When subsequent partition additions cause the array to be reallocated, this pointer becomes stale, leading to a heap use-after-free read. An attacker who can present a crafted block device image (for example, via USB insertion or a loop-mounted disk image) can trigger this flaw without user interaction, as libblkid is invoked automatically by udev/udisks as root on block-device hot-plug events. This could lead to limited information disclosure or denial of service.

### CVE-2026-27456

- **Package:** `libuuid1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-27456](https://avd.aquasec.com/nvd/cve-2026-27456)

util-linux is a random collection of Linux utilities. Prior to version 2.41.4, a TOCTOU (Time-of-Check-Time-of-Use) vulnerability has been identified in the SUID binary /usr/bin/mount from util-linux. The mount binary, when setting up loop devices, validates the source file path with user privileges via fork() + setuid() + realpath(), but subsequently re-canonicalizes and opens it with root privileges (euid=0) without verifying that the path has not been replaced between both operations. Neither O_NOFOLLOW, nor inode comparison, nor post-open fstat() are employed. This allows a local unprivileged user to replace the source file with a symlink pointing to any root-owned file or device during the race window, causing the SUID binary to open and mount it as root. Exploitation requires an /etc/fstab entry with user,loop options whose path points to a directory where the attacker has write permission, and that /usr/bin/mount has the SUID bit set (the default configuration on virtually all Linux distributions). The impact is unauthorized read access to root-protected files and block devices, including backup images, disk volumes, and any file containing a valid filesystem. This issue has been patched in version 2.41.4.

### CVE-2026-3184

- **Package:** `libuuid1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-3184](https://avd.aquasec.com/nvd/cve-2026-3184)

A flaw was found in util-linux. Improper hostname canonicalization in the `login(1)` utility, when invoked with the `-h` option, can modify the supplied remote hostname before setting `PAM_RHOST`. A remote attacker could exploit this by providing a specially crafted hostname, potentially bypassing host-based Pluggable Authentication Modules (PAM) access control rules that rely on fully qualified domain names. This could lead to unauthorized access.

### CVE-2026-13595

- **Package:** `mount`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-13595](https://avd.aquasec.com/nvd/cve-2026-13595)

A flaw was found in the libblkid library of util-linux. During nested partition probing, the BSD, Minix, Solaris x86, and UnixWare partition probers cache a raw pointer to a parent partition entry in a dynamically allocated array. When subsequent partition additions cause the array to be reallocated, this pointer becomes stale, leading to a heap use-after-free read. An attacker who can present a crafted block device image (for example, via USB insertion or a loop-mounted disk image) can trigger this flaw without user interaction, as libblkid is invoked automatically by udev/udisks as root on block-device hot-plug events. This could lead to limited information disclosure or denial of service.

### CVE-2026-27456

- **Package:** `mount`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-27456](https://avd.aquasec.com/nvd/cve-2026-27456)

util-linux is a random collection of Linux utilities. Prior to version 2.41.4, a TOCTOU (Time-of-Check-Time-of-Use) vulnerability has been identified in the SUID binary /usr/bin/mount from util-linux. The mount binary, when setting up loop devices, validates the source file path with user privileges via fork() + setuid() + realpath(), but subsequently re-canonicalizes and opens it with root privileges (euid=0) without verifying that the path has not been replaced between both operations. Neither O_NOFOLLOW, nor inode comparison, nor post-open fstat() are employed. This allows a local unprivileged user to replace the source file with a symlink pointing to any root-owned file or device during the race window, causing the SUID binary to open and mount it as root. Exploitation requires an /etc/fstab entry with user,loop options whose path points to a directory where the attacker has write permission, and that /usr/bin/mount has the SUID bit set (the default configuration on virtually all Linux distributions). The impact is unauthorized read access to root-protected files and block devices, including backup images, disk volumes, and any file containing a valid filesystem. This issue has been patched in version 2.41.4.

### CVE-2026-3184

- **Package:** `mount`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-3184](https://avd.aquasec.com/nvd/cve-2026-3184)

A flaw was found in util-linux. Improper hostname canonicalization in the `login(1)` utility, when invoked with the `-h` option, can modify the supplied remote hostname before setting `PAM_RHOST`. A remote attacker could exploit this by providing a specially crafted hostname, potentially bypassing host-based Pluggable Authentication Modules (PAM) access control rules that rely on fully qualified domain names. This could lead to unauthorized access.

### CVE-2023-50495

- **Package:** `ncurses-base`
- **Installed:** `6.4-4`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2023-50495](https://avd.aquasec.com/nvd/cve-2023-50495)

NCurse v6.4-20230418 was discovered to contain a segmentation fault via the component _nc_wrap_entry().

### CVE-2023-50495

- **Package:** `ncurses-bin`
- **Installed:** `6.4-4`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2023-50495](https://avd.aquasec.com/nvd/cve-2023-50495)

NCurse v6.4-20230418 was discovered to contain a segmentation fault via the component _nc_wrap_entry().

### CVE-2026-106552

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-106552](https://avd.aquasec.com/nvd/cve-2026-106552)

In sftp in OpenSSH before 10.6, a server can trigger directory traversal (causing files to be written to unintended locations) during a recursive copy operation.

### CVE-2026-106585

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-106585](https://avd.aquasec.com/nvd/cve-2026-106585)

In sshd and ssh in OpenSSH before 10.6, there is no check for whether the maximum packet length is exceeded during decompression of highly compressed data.

### CVE-2026-106586

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-106586](https://avd.aquasec.com/nvd/cve-2026-106586)

In sshd in OpenSSH before 10.6, the restrict keyword (in authorized_keys) was supposed to be applicable to tunnel forwarding but was not, a different vulnerability than CVE-2026-73283.

### CVE-2026-59995

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-59995](https://avd.aquasec.com/nvd/cve-2026-59995)

sftp in OpenSSH before 10.4 does not properly constrain the location of downloaded files when "sftp server:/path ." is used with an attacker-controlled server.

### CVE-2026-59996

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-59996](https://avd.aquasec.com/nvd/cve-2026-59996)

scp in OpenSSH before 10.4 may place a file in the parent directory of an intended directory when the copy occurs between two remote destinations.

### CVE-2026-59997

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-59997](https://avd.aquasec.com/nvd/cve-2026-59997)

internal-sftp in sshd in OpenSSH before 10.4 recognizes only the first 9 command-line arguments, which can be important if a later command-line argument would have helped to ensure the intended security properties of an SFTP connection.

### CVE-2026-59998

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-59998](https://avd.aquasec.com/nvd/cve-2026-59998)

sshd in OpenSSH before 10.4 has an undocumented security-relevant behavior: GSSAPIStrictAcceptorCheck has no value if the server is in Windows Active Directory.

### CVE-2026-60001

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-60001](https://avd.aquasec.com/nvd/cve-2026-60001)

sshd in OpenSSH before 10.4 does not always honor the minimum authentication delay.

### CVE-2026-73282

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-73282](https://avd.aquasec.com/nvd/cve-2026-73282)

In ssh in OpenSSH before 10.5, a use-after-free for realloc data can occur if a certain pair of remote-forwarding operations are concurrent.

### CVE-2026-73283

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-73283](https://avd.aquasec.com/nvd/cve-2026-73283)

In sshd in OpenSSH before 10.5, the restrict keyword (in authorized_keys) was supposed to be applicable to tunnel forwarding but was not.

### CVE-2026-15534

- **Package:** `perl-base`
- **Installed:** `5.36.0-7+deb12u4`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-15534](https://avd.aquasec.com/nvd/cve-2026-15534)

Perl versions through 5.45.1 have out-of-bounds heap reads and writes during regular expression matching via an undersized superlinear cache in S_regmatch.

The regex engine's superlinear cache holds one bit per subject position for each participating WHILEM node, so the bit count is the subject length plus one times the number of nodes. Nothing checks that product for positive overflow of the signed 32-bit count: a 286331153 byte subject matched against a pattern with 15 participating nodes stores the count as 14, leaving a two byte cache. The cache is then indexed from the real match position and node number, so reads go past the end of the allocation, and on failure CACHEsayNO sets a bit past it.

A caller that matches an attacker controlled subject of this size against a pattern of this shape can crash the process or corrupt heap memory.

### CVE-2025-7709

- **Package:** `sqlite3`
- **Installed:** `3.40.1-2+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-7709](https://avd.aquasec.com/nvd/cve-2025-7709)

An integer overflow exists in the  FTS5 https://sqlite.org/fts5.html  extension. It occurs when the size of an array of tombstone pointers is calculated and truncated into a 32-bit integer. A pointer to partially controlled data can then be written out of bounds.

### CVE-2026-50812

- **Package:** `sqlite3`
- **Installed:** `3.40.1-2+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-50812](https://avd.aquasec.com/nvd/cve-2026-50812)

A NULL pointer dereference in the SQLite Session Extension in SQLite 3.53.1 and SQLite trunk builds before check-in e807d4e3798efd53 allows an attacker who can supply a malformed changeset blob to cause a denial of service. The issue occurs when sqlite3changeset_apply_v3() applies a corrupt changeset and reaches sqlite3_value_type() with a NULL sqlite3_value pointer.

### CVE-2026-50813

- **Package:** `sqlite3`
- **Installed:** `3.40.1-2+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-50813](https://avd.aquasec.com/nvd/cve-2026-50813)

An issue in SQLite before Fossil check-in 869a51ae84df allows a local attacker to obtain sensitive information via the Session Extension changeset concat/changegroup merge path

### CVE-2026-18477

- **Package:** `tar`
- **Installed:** `1.34+dfsg-1.2+deb12u1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-18477](https://avd.aquasec.com/nvd/cve-2026-18477)

A TOCTOU (Time-of-Check Time-of-Use) vulnerability in GNU tar's incremental dumpdir 'X' rename handling allows a local attacker with write access to a directory being backed up to influence the restore process if the attacker has access to the system where the restore is being performed. During restoration, files or directories may be created, renamed or overwritten outside the intended extraction directory. This could lead to unauthorized file modification or, in some cases, privilege escalation. Exploitation does not require the attacker to modify or craft the archive, and standard backup and restore workflows—including extracting into a newly created directory without using the -P option do not mitigate the issue.

### CVE-2026-18508

- **Package:** `tar`
- **Installed:** `1.34+dfsg-1.2+deb12u1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-18508](https://avd.aquasec.com/nvd/cve-2026-18508)

A flaw was found in GNU tar. When extracting an archive with the --one-top-level option, hardlink targets are not confined to the designated top-level directory and may resolve relative to the extraction working directory. A crafted archive can create hardlinks that escape the intended boundary and, when combined with a preexisting symbolic link under the working directory, may allow writing outside that boundary during a single extraction.

### CVE-2026-5704

- **Package:** `tar`
- **Installed:** `1.34+dfsg-1.2+deb12u1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-5704](https://avd.aquasec.com/nvd/cve-2026-5704)

A flaw was found in tar. A remote attacker could exploit this vulnerability by crafting a malicious archive, leading to hidden file injection with fully attacker-controlled content. This bypasses pre-extraction inspection mechanisms, potentially allowing an attacker to introduce malicious files onto a system without detection.

### CVE-2026-13595

- **Package:** `util-linux`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-13595](https://avd.aquasec.com/nvd/cve-2026-13595)

A flaw was found in the libblkid library of util-linux. During nested partition probing, the BSD, Minix, Solaris x86, and UnixWare partition probers cache a raw pointer to a parent partition entry in a dynamically allocated array. When subsequent partition additions cause the array to be reallocated, this pointer becomes stale, leading to a heap use-after-free read. An attacker who can present a crafted block device image (for example, via USB insertion or a loop-mounted disk image) can trigger this flaw without user interaction, as libblkid is invoked automatically by udev/udisks as root on block-device hot-plug events. This could lead to limited information disclosure or denial of service.

### CVE-2026-27456

- **Package:** `util-linux`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-27456](https://avd.aquasec.com/nvd/cve-2026-27456)

util-linux is a random collection of Linux utilities. Prior to version 2.41.4, a TOCTOU (Time-of-Check-Time-of-Use) vulnerability has been identified in the SUID binary /usr/bin/mount from util-linux. The mount binary, when setting up loop devices, validates the source file path with user privileges via fork() + setuid() + realpath(), but subsequently re-canonicalizes and opens it with root privileges (euid=0) without verifying that the path has not been replaced between both operations. Neither O_NOFOLLOW, nor inode comparison, nor post-open fstat() are employed. This allows a local unprivileged user to replace the source file with a symlink pointing to any root-owned file or device during the race window, causing the SUID binary to open and mount it as root. Exploitation requires an /etc/fstab entry with user,loop options whose path points to a directory where the attacker has write permission, and that /usr/bin/mount has the SUID bit set (the default configuration on virtually all Linux distributions). The impact is unauthorized read access to root-protected files and block devices, including backup images, disk volumes, and any file containing a valid filesystem. This issue has been patched in version 2.41.4.

### CVE-2026-3184

- **Package:** `util-linux`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-3184](https://avd.aquasec.com/nvd/cve-2026-3184)

A flaw was found in util-linux. Improper hostname canonicalization in the `login(1)` utility, when invoked with the `-h` option, can modify the supplied remote hostname before setting `PAM_RHOST`. A remote attacker could exploit this by providing a specially crafted hostname, potentially bypassing host-based Pluggable Authentication Modules (PAM) access control rules that rely on fully qualified domain names. This could lead to unauthorized access.

### CVE-2026-13595

- **Package:** `util-linux-extra`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-13595](https://avd.aquasec.com/nvd/cve-2026-13595)

A flaw was found in the libblkid library of util-linux. During nested partition probing, the BSD, Minix, Solaris x86, and UnixWare partition probers cache a raw pointer to a parent partition entry in a dynamically allocated array. When subsequent partition additions cause the array to be reallocated, this pointer becomes stale, leading to a heap use-after-free read. An attacker who can present a crafted block device image (for example, via USB insertion or a loop-mounted disk image) can trigger this flaw without user interaction, as libblkid is invoked automatically by udev/udisks as root on block-device hot-plug events. This could lead to limited information disclosure or denial of service.

### CVE-2026-27456

- **Package:** `util-linux-extra`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-27456](https://avd.aquasec.com/nvd/cve-2026-27456)

util-linux is a random collection of Linux utilities. Prior to version 2.41.4, a TOCTOU (Time-of-Check-Time-of-Use) vulnerability has been identified in the SUID binary /usr/bin/mount from util-linux. The mount binary, when setting up loop devices, validates the source file path with user privileges via fork() + setuid() + realpath(), but subsequently re-canonicalizes and opens it with root privileges (euid=0) without verifying that the path has not been replaced between both operations. Neither O_NOFOLLOW, nor inode comparison, nor post-open fstat() are employed. This allows a local unprivileged user to replace the source file with a symlink pointing to any root-owned file or device during the race window, causing the SUID binary to open and mount it as root. Exploitation requires an /etc/fstab entry with user,loop options whose path points to a directory where the attacker has write permission, and that /usr/bin/mount has the SUID bit set (the default configuration on virtually all Linux distributions). The impact is unauthorized read access to root-protected files and block devices, including backup images, disk volumes, and any file containing a valid filesystem. This issue has been patched in version 2.41.4.

### CVE-2026-3184

- **Package:** `util-linux-extra`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-3184](https://avd.aquasec.com/nvd/cve-2026-3184)

A flaw was found in util-linux. Improper hostname canonicalization in the `login(1)` utility, when invoked with the `-h` option, can modify the supplied remote hostname before setting `PAM_RHOST`. A remote attacker could exploit this by providing a specially crafted hostname, potentially bypassing host-based Pluggable Authentication Modules (PAM) access control rules that rely on fully qualified domain names. This could lead to unauthorized access.

### CVE-2026-27171

- **Package:** `zlib1g`
- **Installed:** `1:1.2.13.dfsg-1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-27171](https://avd.aquasec.com/nvd/cve-2026-27171)

zlib before 1.3.2 allows CPU consumption via crc32_combine64 and crc32_combine_gen64 because x2nmodp can do right shifts within a loop that has no termination condition.

### CVE-2026-85091

- **Package:** `zlib1g`
- **Installed:** `1:1.2.13.dfsg-1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-85091](https://avd.aquasec.com/nvd/cve-2026-85091)

zlib versions 1.3.1.2 through 1.3.2 contain a heap buffer overflow vulnerability in the gz_vacate() function when processing non-blocking gzwrite() operations with stale external buffer pointers. Attackers can trigger the overflow by calling gzprintf() or gzvprintf() after a write stall, causing an unchecked memmove() to write beyond the internal input buffer boundary.

## Low (120)

### CVE-2011-3374

- **Package:** `apt`
- **Installed:** `2.6.1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2011-3374](https://avd.aquasec.com/nvd/cve-2011-3374)

It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyring, leading to a potential man-in-the-middle attack.

### TEMP-0841856-B18BAF

- **Package:** `bash`
- **Installed:** `5.2.15-2+b13`
- **Fixed in:** *No fix available*
- **Reference:** [TEMP-0841856-B18BAF](https://security-tracker.debian.org/tracker/TEMP-0841856-B18BAF)

### CVE-2022-0563

- **Package:** `bsdutils`
- **Installed:** `1:2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2022-0563](https://avd.aquasec.com/nvd/cve-2022-0563)

A flaw was found in the util-linux chfn and chsh utilities when compiled with Readline support. The Readline library uses an "INPUTRC" environment variable to get a path to the library config file. When the library cannot parse the specified file, it prints an error message containing data from the file. This flaw allows an unprivileged user to read root-owned files, potentially leading to privilege escalation. This flaw affects util-linux versions prior to 2.37.4.

### CVE-2025-14104

- **Package:** `bsdutils`
- **Installed:** `1:2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-14104](https://avd.aquasec.com/nvd/cve-2025-14104)

A flaw was found in util-linux. This vulnerability allows a heap buffer overread when processing 256-byte usernames, specifically within the `setpwnam()` function, affecting SUID (Set User ID) login-utils utilities writing to the password database.

### CVE-2016-2781

- **Package:** `coreutils`
- **Installed:** `9.1-1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2016-2781](https://avd.aquasec.com/nvd/cve-2016-2781)

chroot in GNU coreutils, when used with --userspec, allows local users to escape to the parent session via a crafted TIOCSTI ioctl call, which pushes characters to the terminal's input buffer.

### CVE-2017-18018

- **Package:** `coreutils`
- **Installed:** `9.1-1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2017-18018](https://avd.aquasec.com/nvd/cve-2017-18018)

In GNU Coreutils through 8.29, chown-core.c in chown and chgrp does not prevent replacement of a plain file with a symlink during use of the POSIX "-R -L" options, which allows local users to modify the ownership of arbitrary files by leveraging a race condition.

### CVE-2025-5278

- **Package:** `coreutils`
- **Installed:** `9.1-1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-5278](https://avd.aquasec.com/nvd/cve-2025-5278)

A flaw was found in GNU Coreutils. The sort utility's begfield() function is vulnerable to a heap buffer under-read. The program may access memory outside the allocated buffer if a user runs a crafted command using the traditional key format. A malicious input could lead to a crash or leak sensitive data.

### CVE-2026-56391

- **Package:** `coreutils`
- **Installed:** `9.1-1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-56391](https://avd.aquasec.com/nvd/cve-2026-56391)

GNU coreutils uniq is vulnerable to an out‑of‑bounds read due to incorrect handling of multibyte input when the -w (--check-chars) option is used. The find_field() function miscalculates the byte length of characters by repeatedly processing a fixed pointer instead of advancing through the input, resulting in an inflated length value. 
This incorrect length is later used in a memcmp operation, causing reads beyond the allocated buffer when processing crafted multibyte input.

When running GNU coreutils uniq with attacker-provided arguments, this behavior leads to a crash and potential adjacent heap memory exposure.


This issue has been fixed in the commit d64e35a8a4c0e4608321433e0d84d917e4e36371.

### CVE-2026-56392

- **Package:** `coreutils`
- **Installed:** `9.1-1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-56392](https://avd.aquasec.com/nvd/cve-2026-56392)

GNU coreutils unexpand is vulnerable to a heap-based buffer overflow due to an integer overflow during buffer allocation when processing large tab stop (-t) values. The multiplication used to calculate the allocation size can wrap around, resulting in an undersized buffer.
When processing crafted input, subsequent writes exceed the allocated memory, leading to an out‑of‑bounds heap write.

When running GNU coreutils unexpand with attacker-provided large tab stop (-t) arguments, this behavior leads to a crash and potentially achieve a heap write primitive depending on memory layout.










This issue has been fixed in the commit b60a159fdc5bfcf9988d3a4cb6f53abe8ad5d35d

### CVE-2026-102473

- **Package:** `dash`
- **Installed:** `0.5.12-2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-102473](https://avd.aquasec.com/nvd/cve-2026-102473)

A flaw was found in dash. When built without libc fnmatch, the internal pmatch() matcher implements * by unbounded recursion over candidate positions. A local user who can plant filenames, or otherwise feed that matcher, can make a short multi-star pattern such as *.*.*.*.*.tar.gz consume excessive CPU.

### CVE-2026-102474

- **Package:** `dash`
- **Installed:** `0.5.12-2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-102474](https://avd.aquasec.com/nvd/cve-2026-102474)

A flaw was found in dash. The printf builtin reserves four bytes before converting a Unicode \u or \U escape, but the multi-byte token can need five or six bytes. A local user who can supply such an escape to dash printf or echo %b, including through dash -c and a positional argument, can write one or two bytes past that reservation.

### CVE-2026-53910

- **Package:** `diffutils`
- **Installed:** `1:3.8-4`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-53910](https://avd.aquasec.com/nvd/cve-2026-53910)

diff3 tool from GNU diffutils is vulnerable to a heap‑based buffer overflow due to multiple signed integer overflows in line‑mapping calculations. Incorrect arithmetic in mapping line ranges can result in corrupted values being used for memory allocation and loop bounds.
When processing crafted diff output, these overflows may cause the application to allocate insufficient memory and subsequently perform out‑of‑bounds writes during internal processing. 
An attacker who can control the output of the diff program used by diff3 (e.g. via --diff-program pointing to a malicious script) can trigger out-of-bounds writes, resulting in a crash and potentially remote code execution depending on the environment.


This issue has been fixed in commit 9ff04d5b84743e331e80b589335a52c5480d1815 

NOTE:
The project maintainers claim that this is not a security issue. They state that the worst outcome this issue can cause is a crash of diff and that it cannot be used to escalate privileges.

### CVE-2022-27943

- **Package:** `gcc-12-base`
- **Installed:** `12.2.0-14+deb12u1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2022-27943](https://avd.aquasec.com/nvd/cve-2022-27943)

libiberty/rust-demangle.c in GNU GCC 11.2 allows stack consumption in demangle_const, as demonstrated by nm-new.

### CVE-2022-3219

- **Package:** `gpgv`
- **Installed:** `2.2.40-1.1+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2022-3219](https://avd.aquasec.com/nvd/cve-2022-3219)

GnuPG can be made to spin on a relatively small input by (for example) crafting a public key with thousands of signatures attached, compressed down to just a few KB.

### CVE-2026-105712

- **Package:** `gpgv`
- **Installed:** `2.2.40-1.1+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-105712](https://avd.aquasec.com/nvd/cve-2026-105712)

gpgtar in GnuPG before 2.5.19 can allow file overwrite via crafted data in an archive. When extracting an untrusted archive with --directory (aka -C) into an existing directory containing a pre-existing symlink, gpgtar can follow that symlink and create or overwrite a file outside the selected extraction directory. The write is limited by the extraction user's filesystem permissions. An archive extracted into a fresh empty directory does not have this risk.

### CVE-2026-57062

- **Package:** `gpgv`
- **Installed:** `2.2.40-1.1+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-57062](https://avd.aquasec.com/nvd/cve-2026-57062)

CMS (Cryptographic Message Syntax) parsing in gpgsm in GnuPG through 2.5.20 mishandles the CMS format for AES-GCM because aes-ICVlen is supposed to be 12 bytes but 4 bytes is accepted. NOTE: this is related to CVE-2026-34182.

### CVE-2011-3374

- **Package:** `libapt-pkg6.0`
- **Installed:** `2.6.1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2011-3374](https://avd.aquasec.com/nvd/cve-2011-3374)

It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyring, leading to a potential man-in-the-middle attack.

### CVE-2022-0563

- **Package:** `libblkid1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2022-0563](https://avd.aquasec.com/nvd/cve-2022-0563)

A flaw was found in the util-linux chfn and chsh utilities when compiled with Readline support. The Readline library uses an "INPUTRC" environment variable to get a path to the library config file. When the library cannot parse the specified file, it prints an error message containing data from the file. This flaw allows an unprivileged user to read root-owned files, potentially leading to privilege escalation. This flaw affects util-linux versions prior to 2.37.4.

### CVE-2025-14104

- **Package:** `libblkid1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-14104](https://avd.aquasec.com/nvd/cve-2025-14104)

A flaw was found in util-linux. This vulnerability allows a heap buffer overread when processing 256-byte usernames, specifically within the `setpwnam()` function, affecting SUID (Set User ID) login-utils utilities writing to the password database.

### CVE-2010-4756

- **Package:** `libc-bin`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2010-4756](https://avd.aquasec.com/nvd/cve-2010-4756)

The glob implementation in the GNU C Library (aka glibc or libc6) allows remote authenticated users to cause a denial of service (CPU and memory consumption) via crafted glob expressions that do not match any pathnames, as demonstrated by glob expressions in STAT commands to an FTP daemon, a different vulnerability than CVE-2010-2632.

### CVE-2018-20796

- **Package:** `libc-bin`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2018-20796](https://avd.aquasec.com/nvd/cve-2018-20796)

In the GNU C Library (aka glibc or libc6) through 2.29, check_dst_limits_calc_pos_1 in posix/regexec.c has Uncontrolled Recursion, as demonstrated by '(\227|)(\\1\\1|t1|\\\2537)+' in grep.

### CVE-2019-1010022

- **Package:** `libc-bin`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2019-1010022](https://avd.aquasec.com/nvd/cve-2019-1010022)

GNU Libc current is affected by: Mitigation bypass. The impact is: Attacker may bypass stack guard protection. The component is: nptl. The attack vector is: Exploit stack buffer overflow vulnerability and use this bypass vulnerability to bypass stack guard. NOTE: Upstream comments indicate "this is being treated as a non-security bug and no real threat.

### CVE-2019-1010023

- **Package:** `libc-bin`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2019-1010023](https://avd.aquasec.com/nvd/cve-2019-1010023)

GNU Libc current is affected by: Re-mapping current loaded library with malicious ELF file. The impact is: In worst case attacker may evaluate privileges. The component is: libld. The attack vector is: Attacker sends 2 ELF files to victim and asks to run ldd on it. ldd execute code. NOTE: Upstream comments indicate "this is being treated as a non-security bug and no real threat.

### CVE-2019-1010024

- **Package:** `libc-bin`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2019-1010024](https://avd.aquasec.com/nvd/cve-2019-1010024)

GNU Libc current is affected by: Mitigation bypass. The impact is: Attacker may bypass ASLR using cache of thread stack and heap. The component is: glibc. NOTE: Upstream comments indicate "this is being treated as a non-security bug and no real threat.

### CVE-2019-1010025

- **Package:** `libc-bin`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2019-1010025](https://avd.aquasec.com/nvd/cve-2019-1010025)

GNU Libc current is affected by: Mitigation bypass. The impact is: Attacker may guess the heap addresses of pthread_created thread. The component is: glibc. NOTE: the vendor's position is "ASLR bypass itself is not a vulnerability.

### CVE-2019-9192

- **Package:** `libc-bin`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2019-9192](https://avd.aquasec.com/nvd/cve-2019-9192)

In the GNU C Library (aka glibc or libc6) through 2.29, check_dst_limits_calc_pos_1 in posix/regexec.c has Uncontrolled Recursion, as demonstrated by '(|)(\\1\\1)*' in grep, a different issue than CVE-2018-20796. NOTE: the software maintainer disputes that this is a vulnerability because the behavior occurs only with a crafted pattern

### CVE-2026-97399

- **Package:** `libc-bin`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-97399](https://avd.aquasec.com/nvd/cve-2026-97399)

The strncasecmp function in the GNU C Library 2.24 and later optimized for the Power8 architecture may read one byte beyond the input size limit, which may crash a program when that byte is not readable.

This condition may happen when the input strings to the strncasecmp function are attacker controlled in an application and they match all the way up to the edge of their page and the neighbouring page is either not mapped or is not readable.

### CVE-2010-4756

- **Package:** `libc6`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2010-4756](https://avd.aquasec.com/nvd/cve-2010-4756)

The glob implementation in the GNU C Library (aka glibc or libc6) allows remote authenticated users to cause a denial of service (CPU and memory consumption) via crafted glob expressions that do not match any pathnames, as demonstrated by glob expressions in STAT commands to an FTP daemon, a different vulnerability than CVE-2010-2632.

### CVE-2018-20796

- **Package:** `libc6`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2018-20796](https://avd.aquasec.com/nvd/cve-2018-20796)

In the GNU C Library (aka glibc or libc6) through 2.29, check_dst_limits_calc_pos_1 in posix/regexec.c has Uncontrolled Recursion, as demonstrated by '(\227|)(\\1\\1|t1|\\\2537)+' in grep.

### CVE-2019-1010022

- **Package:** `libc6`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2019-1010022](https://avd.aquasec.com/nvd/cve-2019-1010022)

GNU Libc current is affected by: Mitigation bypass. The impact is: Attacker may bypass stack guard protection. The component is: nptl. The attack vector is: Exploit stack buffer overflow vulnerability and use this bypass vulnerability to bypass stack guard. NOTE: Upstream comments indicate "this is being treated as a non-security bug and no real threat.

### CVE-2019-1010023

- **Package:** `libc6`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2019-1010023](https://avd.aquasec.com/nvd/cve-2019-1010023)

GNU Libc current is affected by: Re-mapping current loaded library with malicious ELF file. The impact is: In worst case attacker may evaluate privileges. The component is: libld. The attack vector is: Attacker sends 2 ELF files to victim and asks to run ldd on it. ldd execute code. NOTE: Upstream comments indicate "this is being treated as a non-security bug and no real threat.

### CVE-2019-1010024

- **Package:** `libc6`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2019-1010024](https://avd.aquasec.com/nvd/cve-2019-1010024)

GNU Libc current is affected by: Mitigation bypass. The impact is: Attacker may bypass ASLR using cache of thread stack and heap. The component is: glibc. NOTE: Upstream comments indicate "this is being treated as a non-security bug and no real threat.

### CVE-2019-1010025

- **Package:** `libc6`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2019-1010025](https://avd.aquasec.com/nvd/cve-2019-1010025)

GNU Libc current is affected by: Mitigation bypass. The impact is: Attacker may guess the heap addresses of pthread_created thread. The component is: glibc. NOTE: the vendor's position is "ASLR bypass itself is not a vulnerability.

### CVE-2019-9192

- **Package:** `libc6`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2019-9192](https://avd.aquasec.com/nvd/cve-2019-9192)

In the GNU C Library (aka glibc or libc6) through 2.29, check_dst_limits_calc_pos_1 in posix/regexec.c has Uncontrolled Recursion, as demonstrated by '(|)(\\1\\1)*' in grep, a different issue than CVE-2018-20796. NOTE: the software maintainer disputes that this is a vulnerability because the behavior occurs only with a crafted pattern

### CVE-2026-97399

- **Package:** `libc6`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-97399](https://avd.aquasec.com/nvd/cve-2026-97399)

The strncasecmp function in the GNU C Library 2.24 and later optimized for the Power8 architecture may read one byte beyond the input size limit, which may crash a program when that byte is not readable.

This condition may happen when the input strings to the strncasecmp function are attacker controlled in an application and they match all the way up to the edge of their page and the neighbouring page is either not mapped or is not readable.

### CVE-2022-27943

- **Package:** `libgcc-s1`
- **Installed:** `12.2.0-14+deb12u1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2022-27943](https://avd.aquasec.com/nvd/cve-2022-27943)

libiberty/rust-demangle.c in GNU GCC 11.2 allows stack consumption in demangle_const, as demonstrated by nm-new.

### CVE-2018-6829

- **Package:** `libgcrypt20`
- **Installed:** `1.10.1-3+deb12u1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2018-6829](https://avd.aquasec.com/nvd/cve-2018-6829)

cipher/elgamal.c in Libgcrypt through 1.8.2, when used to encrypt messages directly, improperly encodes plaintexts, which allows attackers to obtain sensitive information by reading ciphertext data (i.e., it does not have semantic security in face of a ciphertext-only attack). The Decisional Diffie-Hellman (DDH) assumption does not hold for Libgcrypt's ElGamal implementation.

### CVE-2024-2236

- **Package:** `libgcrypt20`
- **Installed:** `1.10.1-3+deb12u1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2024-2236](https://avd.aquasec.com/nvd/cve-2024-2236)

A timing-based side-channel flaw was found in libgcrypt's RSA implementation. This issue may allow a remote attacker to initiate a Bleichenbacher-style attack, which can lead to the decryption of RSA ciphertexts.

### CVE-2011-3389

- **Package:** `libgnutls30`
- **Installed:** `3.7.9-2+deb12u7`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2011-3389](https://avd.aquasec.com/nvd/cve-2011-3389)

The SSL protocol, as used in certain configurations in Microsoft Windows and Microsoft Internet Explorer, Mozilla Firefox, Google Chrome, Opera, and other products, encrypts data by using CBC mode with chained initialization vectors, which allows man-in-the-middle attackers to obtain plaintext HTTP headers via a blockwise chosen-boundary attack (BCBA) on an HTTPS session, in conjunction with JavaScript code that uses (1) the HTML5 WebSocket API, (2) the Java URLConnection API, or (3) the Silverlight WebClient API, aka a "BEAST" attack.

### CVE-2026-67693

- **Package:** `libgnutls30`
- **Installed:** `3.7.9-2+deb12u7`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-67693](https://avd.aquasec.com/nvd/cve-2026-67693)

An issue in gnutls v.3.8.13 allows an attacker to obtain sensitive information via failing to reject end-entity X.509 certificates that contain a contradictory combination of Key Usage (KU) and Extended Key Usage (EKU)

### CVE-2026-88647

- **Package:** `libgnutls30`
- **Installed:** `3.7.9-2+deb12u7`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-88647](https://avd.aquasec.com/nvd/cve-2026-88647)

A hostname verification bypass in GnuTLS v3.8.13 allows attackers to circumvent the Common Name fallback mechanism and eavesdrop on communications via a crafted certificate.

### CVE-2026-88648

- **Package:** `libgnutls30`
- **Installed:** `3.7.9-2+deb12u7`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-88648](https://avd.aquasec.com/nvd/cve-2026-88648)

Incomplete X.509 implementation in GnuTLS v3.8.13 allows attackers controlling a subordinate Certificate Authority to bypass cross-domain PKI restrictions and issue unauthorized certificates.

### CVE-2026-95184

- **Package:** `libgnutls30`
- **Installed:** `3.7.9-2+deb12u7`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-95184](https://avd.aquasec.com/nvd/cve-2026-95184)

Improper certificate validation in gnutls v3.8.13 causes the application to reject legitimate certificates for valid users, leading to a Denial of Service (DoS).

### CVE-2026-95209

- **Package:** `libgnutls30`
- **Installed:** `3.7.9-2+deb12u7`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-95209](https://avd.aquasec.com/nvd/cve-2026-95209)

An issue in gnutls v3.8.13 causes legitimate CA certificates to be rejected, leading to a Denial of Service (DoS).

### CVE-2026-95210

- **Package:** `libgnutls30`
- **Installed:** `3.7.9-2+deb12u7`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-95210](https://avd.aquasec.com/nvd/cve-2026-95210)

Improper certificate validation in gnutls v3.8.13 causes the application to accept certificates containing invalid extensions.

### CVE-2018-5709

- **Package:** `libgssapi-krb5-2`
- **Installed:** `1.20.1-2+deb12u5`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2018-5709](https://avd.aquasec.com/nvd/cve-2018-5709)

An issue was discovered in MIT Kerberos 5 (aka krb5) through 1.16. There is a variable "dbentry->n_key_data" in kadmin/dbutil/dump.c that can store 16-bit data but unknowingly the developer has assigned a "u4" variable to it, which is for 32-bit data. An attacker can use this vulnerability to affect other artifacts of the database as we know that a Kerberos database dump file contains trusted data.

### CVE-2024-26458

- **Package:** `libgssapi-krb5-2`
- **Installed:** `1.20.1-2+deb12u5`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2024-26458](https://avd.aquasec.com/nvd/cve-2024-26458)

Kerberos 5 (aka krb5) 1.21.2 contains a memory leak in /krb5/src/lib/rpc/pmap_rmt.c.

### CVE-2024-26461

- **Package:** `libgssapi-krb5-2`
- **Installed:** `1.20.1-2+deb12u5`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2024-26461](https://avd.aquasec.com/nvd/cve-2024-26461)

Kerberos 5 (aka krb5) 1.21.2 contains a memory leak vulnerability in /krb5/src/lib/gssapi/krb5/k5sealv3.c.

### CVE-2026-11850

- **Package:** `libgssapi-krb5-2`
- **Installed:** `1.20.1-2+deb12u5`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-11850](https://avd.aquasec.com/nvd/cve-2026-11850)

An integer underflow vulnerability was found in MIT krb5 in the berval2tl_data() function in plugins/kdb/ldap/libkdb_ldap/ldap_principal2.c. The function performs an unsigned subtraction (bv_len - 2) without a prior bounds check. When bv_len is 0 or 1, the subtraction wraps to a large value which is then truncated to uint16_t, yielding 0xFFFE (65534) or 0xFFFF (65535). The subsequent malloc succeeds and memcpy reads up to 65534 bytes from a 0-1 byte buffer, resulting in a heap out-of-bounds read.
The attack vector involves a malicious or compromised LDAP KDB backend returning a krbExtraData attribute with bv_len < 2, triggering the underflow when the KDC or kadmind reads principal data.

### CVE-2018-5709

- **Package:** `libk5crypto3`
- **Installed:** `1.20.1-2+deb12u5`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2018-5709](https://avd.aquasec.com/nvd/cve-2018-5709)

An issue was discovered in MIT Kerberos 5 (aka krb5) through 1.16. There is a variable "dbentry->n_key_data" in kadmin/dbutil/dump.c that can store 16-bit data but unknowingly the developer has assigned a "u4" variable to it, which is for 32-bit data. An attacker can use this vulnerability to affect other artifacts of the database as we know that a Kerberos database dump file contains trusted data.

### CVE-2024-26458

- **Package:** `libk5crypto3`
- **Installed:** `1.20.1-2+deb12u5`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2024-26458](https://avd.aquasec.com/nvd/cve-2024-26458)

Kerberos 5 (aka krb5) 1.21.2 contains a memory leak in /krb5/src/lib/rpc/pmap_rmt.c.

### CVE-2024-26461

- **Package:** `libk5crypto3`
- **Installed:** `1.20.1-2+deb12u5`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2024-26461](https://avd.aquasec.com/nvd/cve-2024-26461)

Kerberos 5 (aka krb5) 1.21.2 contains a memory leak vulnerability in /krb5/src/lib/gssapi/krb5/k5sealv3.c.

### CVE-2026-11850

- **Package:** `libk5crypto3`
- **Installed:** `1.20.1-2+deb12u5`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-11850](https://avd.aquasec.com/nvd/cve-2026-11850)

An integer underflow vulnerability was found in MIT krb5 in the berval2tl_data() function in plugins/kdb/ldap/libkdb_ldap/ldap_principal2.c. The function performs an unsigned subtraction (bv_len - 2) without a prior bounds check. When bv_len is 0 or 1, the subtraction wraps to a large value which is then truncated to uint16_t, yielding 0xFFFE (65534) or 0xFFFF (65535). The subsequent malloc succeeds and memcpy reads up to 65534 bytes from a 0-1 byte buffer, resulting in a heap out-of-bounds read.
The attack vector involves a malicious or compromised LDAP KDB backend returning a krbExtraData attribute with bv_len < 2, triggering the underflow when the KDC or kadmind reads principal data.

### CVE-2018-5709

- **Package:** `libkrb5-3`
- **Installed:** `1.20.1-2+deb12u5`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2018-5709](https://avd.aquasec.com/nvd/cve-2018-5709)

An issue was discovered in MIT Kerberos 5 (aka krb5) through 1.16. There is a variable "dbentry->n_key_data" in kadmin/dbutil/dump.c that can store 16-bit data but unknowingly the developer has assigned a "u4" variable to it, which is for 32-bit data. An attacker can use this vulnerability to affect other artifacts of the database as we know that a Kerberos database dump file contains trusted data.

### CVE-2024-26458

- **Package:** `libkrb5-3`
- **Installed:** `1.20.1-2+deb12u5`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2024-26458](https://avd.aquasec.com/nvd/cve-2024-26458)

Kerberos 5 (aka krb5) 1.21.2 contains a memory leak in /krb5/src/lib/rpc/pmap_rmt.c.

### CVE-2024-26461

- **Package:** `libkrb5-3`
- **Installed:** `1.20.1-2+deb12u5`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2024-26461](https://avd.aquasec.com/nvd/cve-2024-26461)

Kerberos 5 (aka krb5) 1.21.2 contains a memory leak vulnerability in /krb5/src/lib/gssapi/krb5/k5sealv3.c.

### CVE-2026-11850

- **Package:** `libkrb5-3`
- **Installed:** `1.20.1-2+deb12u5`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-11850](https://avd.aquasec.com/nvd/cve-2026-11850)

An integer underflow vulnerability was found in MIT krb5 in the berval2tl_data() function in plugins/kdb/ldap/libkdb_ldap/ldap_principal2.c. The function performs an unsigned subtraction (bv_len - 2) without a prior bounds check. When bv_len is 0 or 1, the subtraction wraps to a large value which is then truncated to uint16_t, yielding 0xFFFE (65534) or 0xFFFF (65535). The subsequent malloc succeeds and memcpy reads up to 65534 bytes from a 0-1 byte buffer, resulting in a heap out-of-bounds read.
The attack vector involves a malicious or compromised LDAP KDB backend returning a krbExtraData attribute with bv_len < 2, triggering the underflow when the KDC or kadmind reads principal data.

### CVE-2018-5709

- **Package:** `libkrb5support0`
- **Installed:** `1.20.1-2+deb12u5`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2018-5709](https://avd.aquasec.com/nvd/cve-2018-5709)

An issue was discovered in MIT Kerberos 5 (aka krb5) through 1.16. There is a variable "dbentry->n_key_data" in kadmin/dbutil/dump.c that can store 16-bit data but unknowingly the developer has assigned a "u4" variable to it, which is for 32-bit data. An attacker can use this vulnerability to affect other artifacts of the database as we know that a Kerberos database dump file contains trusted data.

### CVE-2024-26458

- **Package:** `libkrb5support0`
- **Installed:** `1.20.1-2+deb12u5`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2024-26458](https://avd.aquasec.com/nvd/cve-2024-26458)

Kerberos 5 (aka krb5) 1.21.2 contains a memory leak in /krb5/src/lib/rpc/pmap_rmt.c.

### CVE-2024-26461

- **Package:** `libkrb5support0`
- **Installed:** `1.20.1-2+deb12u5`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2024-26461](https://avd.aquasec.com/nvd/cve-2024-26461)

Kerberos 5 (aka krb5) 1.21.2 contains a memory leak vulnerability in /krb5/src/lib/gssapi/krb5/k5sealv3.c.

### CVE-2026-11850

- **Package:** `libkrb5support0`
- **Installed:** `1.20.1-2+deb12u5`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-11850](https://avd.aquasec.com/nvd/cve-2026-11850)

An integer underflow vulnerability was found in MIT krb5 in the berval2tl_data() function in plugins/kdb/ldap/libkdb_ldap/ldap_principal2.c. The function performs an unsigned subtraction (bv_len - 2) without a prior bounds check. When bv_len is 0 or 1, the subtraction wraps to a large value which is then truncated to uint16_t, yielding 0xFFFE (65534) or 0xFFFF (65535). The subsequent malloc succeeds and memcpy reads up to 65534 bytes from a 0-1 byte buffer, resulting in a heap out-of-bounds read.
The attack vector involves a malicious or compromised LDAP KDB backend returning a krbExtraData attribute with bv_len < 2, triggering the underflow when the KDC or kadmind reads principal data.

### CVE-2022-0563

- **Package:** `libmount1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2022-0563](https://avd.aquasec.com/nvd/cve-2022-0563)

A flaw was found in the util-linux chfn and chsh utilities when compiled with Readline support. The Readline library uses an "INPUTRC" environment variable to get a path to the library config file. When the library cannot parse the specified file, it prints an error message containing data from the file. This flaw allows an unprivileged user to read root-owned files, potentially leading to privilege escalation. This flaw affects util-linux versions prior to 2.37.4.

### CVE-2025-14104

- **Package:** `libmount1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-14104](https://avd.aquasec.com/nvd/cve-2025-14104)

A flaw was found in util-linux. This vulnerability allows a heap buffer overread when processing 256-byte usernames, specifically within the `setpwnam()` function, affecting SUID (Set User ID) login-utils utilities writing to the password database.

### CVE-2025-6141

- **Package:** `libncursesw6`
- **Installed:** `6.4-4`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-6141](https://avd.aquasec.com/nvd/cve-2025-6141)

A vulnerability has been found in GNU ncurses up to 6.5-20250322 and classified as problematic. This vulnerability affects the function postprocess_termcap of the file tinfo/parse_entry.c. The manipulation leads to stack-based buffer overflow. The attack needs to be approached locally. Upgrading to version 6.5-20250329 is able to address this issue. It is recommended to upgrade the affected component.

### CVE-2022-0563

- **Package:** `libsmartcols1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2022-0563](https://avd.aquasec.com/nvd/cve-2022-0563)

A flaw was found in the util-linux chfn and chsh utilities when compiled with Readline support. The Readline library uses an "INPUTRC" environment variable to get a path to the library config file. When the library cannot parse the specified file, it prints an error message containing data from the file. This flaw allows an unprivileged user to read root-owned files, potentially leading to privilege escalation. This flaw affects util-linux versions prior to 2.37.4.

### CVE-2025-14104

- **Package:** `libsmartcols1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-14104](https://avd.aquasec.com/nvd/cve-2025-14104)

A flaw was found in util-linux. This vulnerability allows a heap buffer overread when processing 256-byte usernames, specifically within the `setpwnam()` function, affecting SUID (Set User ID) login-utils utilities writing to the password database.

### CVE-2021-45346

- **Package:** `libsqlite3-0`
- **Installed:** `3.40.1-2+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2021-45346](https://avd.aquasec.com/nvd/cve-2021-45346)

A Memory Leak vulnerability exists in SQLite Project SQLite3 3.35.1 and 3.37.0 via maliciously crafted SQL Queries (made via editing the Database File), it is possible to query a record, and leak subsequent bytes of memory that extend beyond the record, which could let a malicious user obtain sensitive information. NOTE: The developer disputes this as a vulnerability stating that If you give SQLite a corrupted database file and submit a query against the database, it might read parts of the database that you did not intend or expect.

### CVE-2025-29088

- **Package:** `libsqlite3-0`
- **Installed:** `3.40.1-2+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-29088](https://avd.aquasec.com/nvd/cve-2025-29088)

In SQLite 3.49.0 before 3.49.1, certain argument values to sqlite3_db_config (in the C-language API) can cause a denial of service (application crash). An sz*nBig multiplication is not cast to a 64-bit integer, and consequently some memory allocations may be incorrect.

### CVE-2025-70873

- **Package:** `libsqlite3-0`
- **Installed:** `3.40.1-2+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-70873](https://avd.aquasec.com/nvd/cve-2025-70873)

An information disclosure issue in the zipfileInflate function in the zipfile extension in SQLite v3.51.1 and earlier allows attackers to obtain heap memory via supplying a crafted ZIP file.

### CVE-2025-27587

- **Package:** `libssl3`
- **Installed:** `3.0.22-1~deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-27587](https://avd.aquasec.com/nvd/cve-2025-27587)

OpenSSL 3.0.0 through 3.3.2 on the PowerPC architecture is vulnerable to a Minerva attack, exploitable by measuring the time of signing of random messages using the EVP_DigestSign API, and then using the private key to extract the K value (nonce) from the signatures. Next, based on the bit size of the extracted nonce, one can compare the signing time of full-sized nonces to signatures that used smaller nonces, via statistical tests. There is a side-channel in the P-364 curve that allows private key extraction (also, there is a dependency between the bit size of K and the size of the side channel). NOTE: This CVE is disputed because the OpenSSL security policy explicitly notes that any side channels which require same physical system to be detected are outside of the threat model for the software. The timing signal is so small that it is infeasible to be detected without having the attacking process running on the same physical system.

### CVE-2022-27943

- **Package:** `libstdc++6`
- **Installed:** `12.2.0-14+deb12u1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2022-27943](https://avd.aquasec.com/nvd/cve-2022-27943)

libiberty/rust-demangle.c in GNU GCC 11.2 allows stack consumption in demangle_const, as demonstrated by nm-new.

### CVE-2013-4392

- **Package:** `libsystemd0`
- **Installed:** `252.39-1~deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2013-4392](https://avd.aquasec.com/nvd/cve-2013-4392)

systemd, when updating file permissions, allows local users to change the permissions and SELinux security contexts for arbitrary files via a symlink attack on unspecified files.

### CVE-2023-31437

- **Package:** `libsystemd0`
- **Installed:** `252.39-1~deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2023-31437](https://avd.aquasec.com/nvd/cve-2023-31437)

An issue was discovered in systemd 253. An attacker can modify a sealed log file such that, in some views, not all existing and sealed log messages are displayed. NOTE: the vendor reportedly sent "a reply denying that any of the finding was a security vulnerability."

### CVE-2023-31438

- **Package:** `libsystemd0`
- **Installed:** `252.39-1~deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2023-31438](https://avd.aquasec.com/nvd/cve-2023-31438)

An issue was discovered in systemd 253. An attacker can truncate a sealed log file and then resume log sealing such that checking the integrity shows no error, despite modifications. NOTE: the vendor reportedly sent "a reply denying that any of the finding was a security vulnerability."

### CVE-2023-31439

- **Package:** `libsystemd0`
- **Installed:** `252.39-1~deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2023-31439](https://avd.aquasec.com/nvd/cve-2023-31439)

An issue was discovered in systemd 253. An attacker can modify the contents of past events in a sealed log file and then adjust the file such that checking the integrity shows no error, despite modifications. NOTE: the vendor reportedly sent "a reply denying that any of the finding was a security vulnerability."

### CVE-2026-40228

- **Package:** `libsystemd0`
- **Installed:** `252.39-1~deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-40228](https://avd.aquasec.com/nvd/cve-2026-40228)

In systemd 259, systemd-journald can send ANSI escape sequences to the terminals of arbitrary users when a "logger -p emerg" command is executed, if ForwardToWall=yes is set.

### CVE-2025-13151

- **Package:** `libtasn1-6`
- **Installed:** `4.19.0-2+deb12u1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-13151](https://avd.aquasec.com/nvd/cve-2025-13151)

Stack-based buffer overflow in libtasn1 version: v4.20.0. The function fails to validate the size of input data resulting in a buffer overflow in asn1_expend_octet_string.

### CVE-2025-6141

- **Package:** `libtinfo6`
- **Installed:** `6.4-4`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-6141](https://avd.aquasec.com/nvd/cve-2025-6141)

A vulnerability has been found in GNU ncurses up to 6.5-20250322 and classified as problematic. This vulnerability affects the function postprocess_termcap of the file tinfo/parse_entry.c. The manipulation leads to stack-based buffer overflow. The attack needs to be approached locally. Upgrading to version 6.5-20250329 is able to address this issue. It is recommended to upgrade the affected component.

### CVE-2013-4392

- **Package:** `libudev1`
- **Installed:** `252.39-1~deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2013-4392](https://avd.aquasec.com/nvd/cve-2013-4392)

systemd, when updating file permissions, allows local users to change the permissions and SELinux security contexts for arbitrary files via a symlink attack on unspecified files.

### CVE-2023-31437

- **Package:** `libudev1`
- **Installed:** `252.39-1~deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2023-31437](https://avd.aquasec.com/nvd/cve-2023-31437)

An issue was discovered in systemd 253. An attacker can modify a sealed log file such that, in some views, not all existing and sealed log messages are displayed. NOTE: the vendor reportedly sent "a reply denying that any of the finding was a security vulnerability."

### CVE-2023-31438

- **Package:** `libudev1`
- **Installed:** `252.39-1~deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2023-31438](https://avd.aquasec.com/nvd/cve-2023-31438)

An issue was discovered in systemd 253. An attacker can truncate a sealed log file and then resume log sealing such that checking the integrity shows no error, despite modifications. NOTE: the vendor reportedly sent "a reply denying that any of the finding was a security vulnerability."

### CVE-2023-31439

- **Package:** `libudev1`
- **Installed:** `252.39-1~deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2023-31439](https://avd.aquasec.com/nvd/cve-2023-31439)

An issue was discovered in systemd 253. An attacker can modify the contents of past events in a sealed log file and then adjust the file such that checking the integrity shows no error, despite modifications. NOTE: the vendor reportedly sent "a reply denying that any of the finding was a security vulnerability."

### CVE-2026-40228

- **Package:** `libudev1`
- **Installed:** `252.39-1~deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-40228](https://avd.aquasec.com/nvd/cve-2026-40228)

In systemd 259, systemd-journald can send ANSI escape sequences to the terminals of arbitrary users when a "logger -p emerg" command is executed, if ForwardToWall=yes is set.

### CVE-2022-0563

- **Package:** `libuuid1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2022-0563](https://avd.aquasec.com/nvd/cve-2022-0563)

A flaw was found in the util-linux chfn and chsh utilities when compiled with Readline support. The Readline library uses an "INPUTRC" environment variable to get a path to the library config file. When the library cannot parse the specified file, it prints an error message containing data from the file. This flaw allows an unprivileged user to read root-owned files, potentially leading to privilege escalation. This flaw affects util-linux versions prior to 2.37.4.

### CVE-2025-14104

- **Package:** `libuuid1`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-14104](https://avd.aquasec.com/nvd/cve-2025-14104)

A flaw was found in util-linux. This vulnerability allows a heap buffer overread when processing 256-byte usernames, specifically within the `setpwnam()` function, affecting SUID (Set User ID) login-utils utilities writing to the password database.

### CVE-2007-5686

- **Package:** `login`
- **Installed:** `1:4.13+dfsg1-1+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2007-5686](https://avd.aquasec.com/nvd/cve-2007-5686)

initscripts in rPath Linux 1 sets insecure permissions for the /var/log/btmp file, which allows local users to obtain sensitive information regarding authentication attempts.  NOTE: because sshd detects the insecure permissions and does not log certain events, this also prevents sshd from logging failed authentication attempts by remote attackers.

### CVE-2024-56433

- **Package:** `login`
- **Installed:** `1:4.13+dfsg1-1+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2024-56433](https://avd.aquasec.com/nvd/cve-2024-56433)

shadow-utils (aka shadow) 4.4 through 4.17.0 establishes a default /etc/subuid behavior (e.g., uid 100000 through 165535 for the first user account) that can realistically conflict with the uids of users defined on locally administered networks, potentially leading to account takeover, e.g., by leveraging newuidmap for access to an NFS home directory (or same-host resources in the case of remote logins by these local network users). NOTE: it may also be argued that system administrators should not have assigned uids, within local networks, that are within the range that can occur in /etc/subuid.

### TEMP-0628843-DBAD28

- **Package:** `login`
- **Installed:** `1:4.13+dfsg1-1+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [TEMP-0628843-DBAD28](https://security-tracker.debian.org/tracker/TEMP-0628843-DBAD28)

### CVE-2022-0563

- **Package:** `mount`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2022-0563](https://avd.aquasec.com/nvd/cve-2022-0563)

A flaw was found in the util-linux chfn and chsh utilities when compiled with Readline support. The Readline library uses an "INPUTRC" environment variable to get a path to the library config file. When the library cannot parse the specified file, it prints an error message containing data from the file. This flaw allows an unprivileged user to read root-owned files, potentially leading to privilege escalation. This flaw affects util-linux versions prior to 2.37.4.

### CVE-2025-14104

- **Package:** `mount`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-14104](https://avd.aquasec.com/nvd/cve-2025-14104)

A flaw was found in util-linux. This vulnerability allows a heap buffer overread when processing 256-byte usernames, specifically within the `setpwnam()` function, affecting SUID (Set User ID) login-utils utilities writing to the password database.

### CVE-2025-6141

- **Package:** `ncurses-base`
- **Installed:** `6.4-4`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-6141](https://avd.aquasec.com/nvd/cve-2025-6141)

A vulnerability has been found in GNU ncurses up to 6.5-20250322 and classified as problematic. This vulnerability affects the function postprocess_termcap of the file tinfo/parse_entry.c. The manipulation leads to stack-based buffer overflow. The attack needs to be approached locally. Upgrading to version 6.5-20250329 is able to address this issue. It is recommended to upgrade the affected component.

### CVE-2025-6141

- **Package:** `ncurses-bin`
- **Installed:** `6.4-4`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-6141](https://avd.aquasec.com/nvd/cve-2025-6141)

A vulnerability has been found in GNU ncurses up to 6.5-20250322 and classified as problematic. This vulnerability affects the function postprocess_termcap of the file tinfo/parse_entry.c. The manipulation leads to stack-based buffer overflow. The attack needs to be approached locally. Upgrading to version 6.5-20250329 is able to address this issue. It is recommended to upgrade the affected component.

### CVE-2007-2243

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2007-2243](https://avd.aquasec.com/nvd/cve-2007-2243)

OpenSSH 4.6 and earlier, when ChallengeResponseAuthentication is enabled, allows remote attackers to determine the existence of user accounts by attempting to authenticate via S/KEY, which displays a different response if the user account exists, a similar issue to CVE-2001-1483.

### CVE-2007-2768

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2007-2768](https://avd.aquasec.com/nvd/cve-2007-2768)

OpenSSH, when using OPIE (One-Time Passwords in Everything) for PAM, allows remote attackers to determine the existence of certain user accounts, which displays a different response if the user account exists and is configured to use one-time passwords (OTP), a similar issue to CVE-2007-2243.

### CVE-2008-3234

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2008-3234](https://avd.aquasec.com/nvd/cve-2008-3234)

sshd in OpenSSH 4 on Debian GNU/Linux, and the 20070303 OpenSSH snapshot, allows remote authenticated users to obtain access to arbitrary SELinux roles by appending a :/ (colon slash) sequence, followed by the role name, to the username.

### CVE-2016-20012

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2016-20012](https://avd.aquasec.com/nvd/cve-2016-20012)

OpenSSH through 8.7 allows remote attackers, who have a suspicion that a certain combination of username and public key is known to an SSH server, to test whether this suspicion is correct. This occurs because a challenge is sent only when that combination could be valid for a login session. NOTE: the vendor does not recognize user enumeration as a vulnerability for this product

### CVE-2018-15919

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2018-15919](https://avd.aquasec.com/nvd/cve-2018-15919)

Remotely observable behaviour in auth-gss2.c in OpenSSH through 7.8 could be used by remote attackers to detect existence of users on a target system when GSS2 is in use. NOTE: the discoverer states 'We understand that the OpenSSH developers do not want to treat such a username enumeration (or "oracle") as a vulnerability.'

### CVE-2019-6110

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2019-6110](https://avd.aquasec.com/nvd/cve-2019-6110)

In OpenSSH 7.9, due to accepting and displaying arbitrary stderr output from the server, a malicious server (or Man-in-The-Middle attacker) can manipulate the client output, for example to use ANSI control codes to hide additional files being transferred.

### CVE-2020-14145

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2020-14145](https://avd.aquasec.com/nvd/cve-2020-14145)

The client side in OpenSSH 5.7 through 8.4 has an Observable Discrepancy leading to an information leak in the algorithm negotiation. This allows man-in-the-middle attackers to target initial connection attempts (where no host key for the server has been cached by the client). NOTE: some reports state that 8.5 and 8.6 are also affected.

### CVE-2020-15778

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2020-15778](https://avd.aquasec.com/nvd/cve-2020-15778)

scp in OpenSSH through 8.3p1 allows command injection in the scp.c toremote function, as demonstrated by backtick characters in the destination argument. NOTE: the vendor reportedly has stated that they intentionally omit validation of "anomalous argument transfers" because that could "stand a great chance of breaking existing workflows."

### CVE-2026-106582

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-106582](https://avd.aquasec.com/nvd/cve-2026-106582)

In sshd and ssh in OpenSSH before 10.6, an LZ77 dictionary coder can be used even though this is contraindicated by the arXiv 2609.07709 "Crossing the Streams" findings.

### CVE-2026-106584

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-106584](https://avd.aquasec.com/nvd/cve-2026-106584)

In ssh-keygen in OpenSSH before 10.6, certificates could have incorrect expiration times because of Daylight Saving mishandling. There can be a slightly more severe effect on users in certain Antarctic locations.

### CVE-2026-106587

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-106587](https://avd.aquasec.com/nvd/cve-2026-106587)

In sshd in OpenSSH before 10.6, the value "none" for a configuration option is sometimes interpreted as a filename but was intended to mean that a feature is disabled.

### CVE-2026-73281

- **Package:** `openssh-client`
- **Installed:** `1:9.2p1-2+deb12u10`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-73281](https://avd.aquasec.com/nvd/cve-2026-73281)

In ssh-agent in OpenSSH before 10.5, some operations can occur remotely but were intended to occur only locally, including operations that add tokens or use keys. This is caused by misinteraction between agent locking and the session-bind@openssh.com extension.

### CVE-2025-27587

- **Package:** `openssl`
- **Installed:** `3.0.22-1~deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-27587](https://avd.aquasec.com/nvd/cve-2025-27587)

OpenSSL 3.0.0 through 3.3.2 on the PowerPC architecture is vulnerable to a Minerva attack, exploitable by measuring the time of signing of random messages using the EVP_DigestSign API, and then using the private key to extract the K value (nonce) from the signatures. Next, based on the bit size of the extracted nonce, one can compare the signing time of full-sized nonces to signatures that used smaller nonces, via statistical tests. There is a side-channel in the P-364 curve that allows private key extraction (also, there is a dependency between the bit size of K and the size of the side channel). NOTE: This CVE is disputed because the OpenSSL security policy explicitly notes that any side channels which require same physical system to be detected are outside of the threat model for the software. The timing signal is so small that it is infeasible to be detected without having the attacking process running on the same physical system.

### CVE-2007-5686

- **Package:** `passwd`
- **Installed:** `1:4.13+dfsg1-1+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2007-5686](https://avd.aquasec.com/nvd/cve-2007-5686)

initscripts in rPath Linux 1 sets insecure permissions for the /var/log/btmp file, which allows local users to obtain sensitive information regarding authentication attempts.  NOTE: because sshd detects the insecure permissions and does not log certain events, this also prevents sshd from logging failed authentication attempts by remote attackers.

### CVE-2024-56433

- **Package:** `passwd`
- **Installed:** `1:4.13+dfsg1-1+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2024-56433](https://avd.aquasec.com/nvd/cve-2024-56433)

shadow-utils (aka shadow) 4.4 through 4.17.0 establishes a default /etc/subuid behavior (e.g., uid 100000 through 165535 for the first user account) that can realistically conflict with the uids of users defined on locally administered networks, potentially leading to account takeover, e.g., by leveraging newuidmap for access to an NFS home directory (or same-host resources in the case of remote logins by these local network users). NOTE: it may also be argued that system administrators should not have assigned uids, within local networks, that are within the range that can occur in /etc/subuid.

### TEMP-0628843-DBAD28

- **Package:** `passwd`
- **Installed:** `1:4.13+dfsg1-1+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [TEMP-0628843-DBAD28](https://security-tracker.debian.org/tracker/TEMP-0628843-DBAD28)

### CVE-2011-4116

- **Package:** `perl-base`
- **Installed:** `5.36.0-7+deb12u4`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2011-4116](https://avd.aquasec.com/nvd/cve-2011-4116)

_is_safe in the File::Temp module for Perl does not properly handle symlinks.

### CVE-2023-31486

- **Package:** `perl-base`
- **Installed:** `5.36.0-7+deb12u4`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2023-31486](https://avd.aquasec.com/nvd/cve-2023-31486)

HTTP::Tiny before 0.083, a Perl core module since 5.13.9 and available standalone on CPAN, has an insecure default TLS configuration where users must opt in to verify certificates.

### CVE-2021-45346

- **Package:** `sqlite3`
- **Installed:** `3.40.1-2+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2021-45346](https://avd.aquasec.com/nvd/cve-2021-45346)

A Memory Leak vulnerability exists in SQLite Project SQLite3 3.35.1 and 3.37.0 via maliciously crafted SQL Queries (made via editing the Database File), it is possible to query a record, and leak subsequent bytes of memory that extend beyond the record, which could let a malicious user obtain sensitive information. NOTE: The developer disputes this as a vulnerability stating that If you give SQLite a corrupted database file and submit a query against the database, it might read parts of the database that you did not intend or expect.

### CVE-2025-29088

- **Package:** `sqlite3`
- **Installed:** `3.40.1-2+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-29088](https://avd.aquasec.com/nvd/cve-2025-29088)

In SQLite 3.49.0 before 3.49.1, certain argument values to sqlite3_db_config (in the C-language API) can cause a denial of service (application crash). An sz*nBig multiplication is not cast to a 64-bit integer, and consequently some memory allocations may be incorrect.

### CVE-2025-70873

- **Package:** `sqlite3`
- **Installed:** `3.40.1-2+deb12u2`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-70873](https://avd.aquasec.com/nvd/cve-2025-70873)

An information disclosure issue in the zipfileInflate function in the zipfile extension in SQLite v3.51.1 and earlier allows attackers to obtain heap memory via supplying a crafted ZIP file.

### TEMP-0517018-A83CE6

- **Package:** `sysvinit-utils`
- **Installed:** `3.06-4`
- **Fixed in:** *No fix available*
- **Reference:** [TEMP-0517018-A83CE6](https://security-tracker.debian.org/tracker/TEMP-0517018-A83CE6)

### CVE-2005-2541

- **Package:** `tar`
- **Installed:** `1.34+dfsg-1.2+deb12u1`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2005-2541](https://avd.aquasec.com/nvd/cve-2005-2541)

Tar 1.15.1 does not properly warn the user when extracting setuid or setgid files, which may allow local users or remote attackers to gain privileges.

### TEMP-0290435-0B57B5

- **Package:** `tar`
- **Installed:** `1.34+dfsg-1.2+deb12u1`
- **Fixed in:** *No fix available*
- **Reference:** [TEMP-0290435-0B57B5](https://security-tracker.debian.org/tracker/TEMP-0290435-0B57B5)

### CVE-2022-0563

- **Package:** `util-linux`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2022-0563](https://avd.aquasec.com/nvd/cve-2022-0563)

A flaw was found in the util-linux chfn and chsh utilities when compiled with Readline support. The Readline library uses an "INPUTRC" environment variable to get a path to the library config file. When the library cannot parse the specified file, it prints an error message containing data from the file. This flaw allows an unprivileged user to read root-owned files, potentially leading to privilege escalation. This flaw affects util-linux versions prior to 2.37.4.

### CVE-2025-14104

- **Package:** `util-linux`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-14104](https://avd.aquasec.com/nvd/cve-2025-14104)

A flaw was found in util-linux. This vulnerability allows a heap buffer overread when processing 256-byte usernames, specifically within the `setpwnam()` function, affecting SUID (Set User ID) login-utils utilities writing to the password database.

### CVE-2022-0563

- **Package:** `util-linux-extra`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2022-0563](https://avd.aquasec.com/nvd/cve-2022-0563)

A flaw was found in the util-linux chfn and chsh utilities when compiled with Readline support. The Readline library uses an "INPUTRC" environment variable to get a path to the library config file. When the library cannot parse the specified file, it prints an error message containing data from the file. This flaw allows an unprivileged user to read root-owned files, potentially leading to privilege escalation. This flaw affects util-linux versions prior to 2.37.4.

### CVE-2025-14104

- **Package:** `util-linux-extra`
- **Installed:** `2.38.1-5+deb12u3`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2025-14104](https://avd.aquasec.com/nvd/cve-2025-14104)

A flaw was found in util-linux. This vulnerability allows a heap buffer overread when processing 256-byte usernames, specifically within the `setpwnam()` function, affecting SUID (Set User ID) login-utils utilities writing to the password database.

## Unknown (4)

### CVE-2026-84243

- **Package:** `libc-bin`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-84243](https://avd.aquasec.com/nvd/cve-2026-84243)

The gettext family of functions in the GNU C Library version 2.0 and later accept LANGUAGE environment variable entries that contain '/' or that are equal to "..", unless the program is setuid or setgid (AT_SECURE).  An attacker who can set LANGUAGE in the environment of a program that uses gettext can make it load a message catalog (.mo file) from an arbitrary location in the file system.  A crafted .mo file can crash the program through out-of-range offsets, or supply translations whose format directives do not match the arguments passed by the program.  That causes undefined behaviour in the printf family of functions and may allow arbitrary code execution with the privileges of the program.  The safety of message catalogs relies on them being installed in trusted, read-only locations, and the directory traversal bypasses this.

The fix for CVE-2014-0475 rejects ".." path components in locale names passed to setlocale or taken from the LC_ALL, LC_* and LANG environment variables.  gettext reads LANGUAGE directly and appends each colon-separated entry to the message catalog directory, so that fix did not cover LANGUAGE.

LANGUAGE is only used when the LC_MESSAGES locale is not "C", "C.<encoding>" or "POSIX", so the attacker must also be able to select another installed locale, for example through LANG or LC_ALL.  Exploitation also requires that the attacker can place the crafted file in a location readable by the target program, and that the environment crosses a trust boundary without the program running as AT_SECURE.  An example is an SSH server that accepts LANGUAGE and LANG from clients through the AcceptEnv directive and restricts an account to a forced command; the attacker may use this to escape the restriction.

### CVE-2026-84243

- **Package:** `libc6`
- **Installed:** `2.36-9+deb12u14`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-84243](https://avd.aquasec.com/nvd/cve-2026-84243)

The gettext family of functions in the GNU C Library version 2.0 and later accept LANGUAGE environment variable entries that contain '/' or that are equal to "..", unless the program is setuid or setgid (AT_SECURE).  An attacker who can set LANGUAGE in the environment of a program that uses gettext can make it load a message catalog (.mo file) from an arbitrary location in the file system.  A crafted .mo file can crash the program through out-of-range offsets, or supply translations whose format directives do not match the arguments passed by the program.  That causes undefined behaviour in the printf family of functions and may allow arbitrary code execution with the privileges of the program.  The safety of message catalogs relies on them being installed in trusted, read-only locations, and the directory traversal bypasses this.

The fix for CVE-2014-0475 rejects ".." path components in locale names passed to setlocale or taken from the LC_ALL, LC_* and LANG environment variables.  gettext reads LANGUAGE directly and appends each colon-separated entry to the message catalog directory, so that fix did not cover LANGUAGE.

LANGUAGE is only used when the LC_MESSAGES locale is not "C", "C.<encoding>" or "POSIX", so the attacker must also be able to select another installed locale, for example through LANG or LC_ALL.  Exploitation also requires that the attacker can place the crafted file in a location readable by the target program, and that the environment crosses a trust boundary without the program running as AT_SECURE.  An example is an SSH server that accepts LANGUAGE and LANG from clients through the AcceptEnv directive and restricts an account to a forced command; the attacker may use this to escape the restriction.

### CVE-2026-82560

- **Package:** `perl-base`
- **Installed:** `5.36.0-7+deb12u4`
- **Fixed in:** *No fix available*
- **Reference:** [CVE-2026-82560](https://avd.aquasec.com/nvd/cve-2026-82560)

Pod::Text versions before 6.1.1 for Perl allow CPU and memory exhaustion formatting a POD document whose =over nesting drives the margin to the output width.

Each =over adds its indent to the margin, which wrap() subtracts from the output width to get the space available for text. When that space reaches zero, the line-splitting substitution matches the empty string, and the loop consumes no input while appending the margin padding on every pass.

Formatting an attacker-supplied POD document never returns, and the output grows until memory is exhausted.

### DLA-4867-1

- **Package:** `tzdata`
- **Installed:** `2026e-0+deb12u1`
- **Fixed in:** `2026f-0+deb12u1`

---

*Report generated by Dockhand*
