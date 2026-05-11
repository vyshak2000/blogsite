---
title: "CopyFail (CVE-2026-31431): The Linux Privilege Escalation Flaw You Can't Ignore"
date: 2026-05-11
draft: false
tags:
  - TryHackMe
  - Privilege_Escalation
  - CVE-2026-31431
  - Linux
  - Memory_Corruption
categories:
  - CVE
summary: CopyFail (CVE-2026-31431) is a Linux kernel privilege escalation vulnerability that lets an unprivileged user exploit the AF_ALG Crypto API to write 4 bytes into the page cache of any readable file, enabling them to corrupt executable code in memory and gain root access when a privileged process runs the tampered file. It affects virtually every Linux distribution shipped since 2017, is already being actively exploited in the wild, and the US government has ordered federal agencies to patch by May 15.
---
## **Introduction**

In late April 2026, security firm Theori dropped a vulnerability that sent shockwaves through the Linux security community and for good reason. Dubbed **CopyFail** (CVE-2026-31431), this local privilege escalation flaw sits inside the Linux kernel's `algif_aead` cryptographic module, a component that has quietly shipped in virtually every mainstream Linux distribution since 2017. The attack primitive is deceptively simple: an unprivileged local user writes just 4 controlled bytes into the page cache of any readable executable, corrupting its in-memory representation. When a privileged process subsequently runs that file, the attacker walks away with root.

What makes CopyFail particularly alarming isn't just its elegance; it's the blast radius. A single 732-byte Python script reliably roots Ubuntu 24.04 LTS, RHEL 10.1, Amazon Linux 2023, SUSE 16, Debian, Fedora, and Kubernetes nodes running affected kernels. CISA wasted no time adding it to the Known Exploited Vulnerabilities catalog, with active exploitation already confirmed in the wild and a patch deadline of May 15 for federal agencies. Patches are rolling out, but distribution lag means millions of systems remain exposed right now.

In this post, we'll break down exactly how CopyFail works, what makes it so reliably exploitable, and what your team should be doing today to detect, mitigate, and remediate before you become a statistic.

---

## **What Does CopyFail Actually Do?

At its core, CopyFail abuses a logic flaw in the Linux kernel's AEAD (Authenticated Encryption with Associated Data) socket interface, specifically the `algif_aead` module to perform a controlled write into the **page cache**, the kernel's in-memory store of file contents. Normally, unprivileged users have no business modifying the page cache of files they don't own. CopyFail breaks that assumption entirely.

By crafting a malicious request through the `AF_ALG` crypto API, an attacker can overwrite exactly 4 bytes at a chosen offset within the cached copy of any readable executable on the system including `setuid` binaries like `sudo` or `passwd`. The file on disk remains untouched; only the in-memory version is poisoned. When a privileged process next executes that binary, it runs the attacker's tampered version instead, handing over a root shell.

The scariest part? This doesn't require any special permissions, CVE chaining, or memory corruption tricks. It's a clean, stable, and highly repeatable primitive one that Theori demonstrated with a script that fits in under 800 bytes and works across nearly every Linux distribution built since 2017.

---

## **Key Concepts Behind CopyFail: A thorough Breakdown**

Before we get into the mechanics of the exploit itself, it's essential to build a solid understanding of every subsystem and concept CopyFail touches. This vulnerability is a beautiful example of how multiple legitimate kernel features can be chained together to produce a devastating primitive. Let's go through each one carefully.

### **The Linux Kernel**

The Linux kernel is the privileged core of the operating system. Every process, every file access, every network packet — all of it flows through the kernel at some point. Unlike regular userspace programs that run with limited permissions, the kernel operates in **ring 0** - the highest privilege level available on x86 hardware, with unrestricted access to all memory, all hardware, and all system resources.

Userspace programs communicate with the kernel through **system calls (syscalls)**; a defined interface that lets applications request services like reading a file, allocating memory, or opening a network socket. This boundary is the fundamental security divide in Linux. CopyFail is dangerous precisely because it lets an unprivileged userspace process reach across that boundary and corrupt data that should be exclusively under kernel control.

### **The Linux Kernel Crypto API**

The Linux kernel has a built-in cryptographic framework often just called the **Kernel Crypto API** that provides a centralized, hardware-accelerated library of cryptographic operations for use across the entire kernel. This includes symmetric encryption algorithms like AES, hash functions like SHA-256, and authenticated encryption schemes. Rather than every kernel subsystem or driver reimplementing cryptography from scratch, they all call into this shared framework.

The Kernel Crypto API abstracts over both software implementations and hardware acceleration (via dedicated crypto coprocessors or CPU instructions like AES-NI), choosing the most efficient available backend transparently. It's a well-engineered system the vulnerability isn't in its design philosophy, but in a very specific implementation detail of one of its userspace-facing interfaces.

### **AF_ALG - The Userspace Bridge to the Kernel Crypto API**

`AF_ALG` is an address family similar in concept to `AF_INET` (for TCP/IP sockets) or `AF_UNIX` (for local sockets) that exposes the Kernel Crypto API to userspace programs through a standard socket interface. Introduced in Linux 2.6.38, the idea was to let userspace applications offload cryptographic work to the kernel without needing to bundle their own crypto libraries or make repeated, expensive copies of data between user and kernel memory.

A program using `AF_ALG` opens a special socket, binds it to a specific algorithm (e.g., `"aead(gcm(aes))"`), then sends data through the socket to be encrypted, decrypted, or hashed receiving the result back. From the application's perspective, it looks just like any other socket operation. Under the hood, the kernel is doing all the crypto work in privileged memory.

`AF_ALG` is available to **unprivileged users** by default on most Linux distributions — this is by design, since providing crypto services to normal applications is entirely legitimate. This is the foothold CopyFail starts from. No special permissions are required to open an `AF_ALG` socket.

### **AEAD - Authenticated Encryption with Associated Data**

AEAD is a class of cryptographic algorithm that combines two operations into one: **encryption** (making data unreadable to unauthorized parties) and **authentication** (ensuring the data hasn't been tampered with). The most widely used AEAD algorithm today is **AES-GCM** (AES in Galois/Counter Mode), which is used everywhere from TLS 1.3 to WireGuard VPN to disk encryption.

The "associated data" part refers to additional context like a packet header that isn't encrypted but is still authenticated. This ensures an attacker can't swap out the header on an encrypted packet without detection.

AEAD algorithms are particularly complex to implement correctly at the kernel level because they deal with multiple data streams simultaneously: the plaintext/ciphertext, the authentication tag, and the associated data. This complexity is exactly what gave rise to the bug in CopyFail.

#### **algif_aead: The Vulnerable Module**

`algif_aead` is the specific kernel module that implements the `AF_ALG` interface for AEAD operations. When a userspace program wants to perform AEAD encryption or decryption through an `AF_ALG` socket, `algif_aead` is the code that handles it.

The vulnerability was introduced in **August 2017** via a performance optimization. The optimization was designed to avoid unnecessary memory copies by allowing the module to perform AEAD operations **in-place** modifying a buffer directly rather than copying data from an input buffer to a separate output buffer. This is a common and legitimate performance technique in kernel code. The problem is that the implementation did not correctly account for how memory pages were being referenced and handed off during in-place operations, leading to a situation where a write could escape its intended memory region.

Specifically, the flaw manifests during the handling of the output scatter-gather list; the data structure that describes where the result of the crypto operation should be written. Under certain conditions, the module ends up holding a reference to a page that belongs to the page cache rather than a private, writable buffer and then writes into it.

### **Scatter-Gather Lists (SG Lists)**

To understand the bug precisely, you need to understand scatter-gather lists. When the kernel performs I/O or crypto operations on large or non-contiguous chunks of data, it would be prohibitively expensive to copy everything into a single contiguous buffer first. Instead, the kernel uses **scatter-gather lists**: arrays of `(page, offset, length)` descriptors that collectively describe a logical buffer spread across multiple physical memory pages.

The crypto API uses SG lists extensively. When you pass data to be encrypted, you hand the kernel an SG list pointing to your input pages. When it returns the result, it writes into an SG list pointing to your output pages. The critical invariant is that the output pages must be **private, writable pages owned by the calling process** not pages belonging to shared kernel data structures like the page cache.

The bug in `algif_aead` breaks this invariant. Through the in-place optimization path, the module can be tricked into constructing an output SG list that points directly at a **page cache page**, a page that logically belongs to a file on the filesystem, shared across all processes. When the AEAD operation completes and writes its output, it writes 4 attacker-controlled bytes directly into that page cache page, corrupting the cached contents of the file.

### **The Page Cache**

The page cache is one of the most important performance optimizations in the Linux kernel, and understanding it deeply is central to understanding why CopyFail is so powerful.

When any process reads a file, the kernel loads the file's contents from disk into RAM and stores them in the **page cache** - a region of kernel memory indexed by `(filesystem, inode, offset)`. Subsequent reads of the same file by any process on the system, not just the one that originally read it are served directly from RAM without touching the disk at all. This is why file access feels fast after the first read: you're reading from RAM, not storage.

The page cache is **shared globally** across all processes and all containers on a host. This is a crucial detail. A page cache page for `/usr/bin/sudo` is the same physical memory page whether process A, process B, or a process inside a Docker container reads it. There is only one cached copy.

When a process **executes** a binary, the kernel maps the binary's pages directly from the page cache into the process's virtual address space. This means the page cache doesn't just back file reads — it backs **code execution itself**. If you corrupt a page cache page belonging to an executable, the next process to run that executable will execute your corrupted version.

Crucially, this corruption is **invisible on disk**. The file on the filesystem is completely unchanged. Standard file integrity tools like `sha256sum` run on the file path will report a clean checksum, because they read from disk; not from the page cache. Only tools that specifically compare the in-memory mapped pages against the on-disk contents would detect the tampering.

#### **The Page Cache and Cross-Container Impact**

One frequently overlooked dimension of CopyFail is its **cross-container blast radius**. In containerized environments like Docker, Kubernetes, LXC, etc., containers share the host kernel and, critically, the host's page cache. A container is a process isolation mechanism, not a memory isolation mechanism at the page cache level.

This means an attacker with access to a low-privileged container on a Kubernetes node can corrupt the page cache of a setuid binary on the **host**, or in another container on the same node, simply by targeting the shared page cache. The container boundary provides no protection here. This is particularly alarming in multi-tenant environments like managed Kubernetes clusters or CI/CD runners where untrusted workloads from different teams or customers share the same underlying node.


### **Setuid Binaries**

Unix systems have a special permission mechanism called the **setuid bit**. When an executable file has the setuid bit set, the operating system runs it with the **effective user ID of the file's owner** typically root rather than the user who invoked it. This is how standard tools like `sudo`, `passwd`, `su`, `ping`, and `newgrp` work: a normal user runs them, but they execute with root privileges long enough to do their job (authenticate, change a password, send a raw network packet, etc.) and then drop those privileges.

Setuid binaries are the ideal target for CopyFail. Because they are widely readable (any user can open and read the file which is what the kernel does when building the page cache entry), and because they execute with elevated privileges, corrupting their page cache entry is enough to hijack the privilege escalation they perform by design. An attacker doesn't need to break any cryptography or bypass any security mechanism they just wait for any user on the system (or an automated process) to invoke the targeted setuid binary, and the attacker's injected code runs as root.

---

## **Affected Versions & Components**

| **Distribution**  | **Kernel**              |
| ----------------- | ----------------------- |
| Ubuntu 24.04 LTS  | 6.17.0-1007-aws         |
| Amazon Linux 2023 | 6.18.8-9.213.amzn2023   |
| RHEL 10.1         | 6.12.0-124.45.1.el10_1  |
| SUSE 16           | 6.12.0-160000.9-default |
## Disclosure timeline

- 2026-03-23 - Reported to Linux kernel security team
- 2026-03-24 - Initial acknowledgment
- 2026-03-25 - Patches proposed and reviewed
- 2026-04-01 - Patch committed to mainline
- 2026-04-22 - CVE-2026-31431 assigned
- 2026-04-29 - Public disclosure

---

## **Proof of Concept (PoC) Breakdown**

Now that we have a solid grounding in the underlying concepts, let's walk through exactly how CopyFail turns a cryptographic API quirk into a root shell. The exploit is elegant in its simplicity — no heap sprays, no ROP chains, no brute forcing. Just a precise, stable, and repeatable abuse of legitimate kernel machinery.

#### **Step 1 - Picking a Target**

The first thing the attacker does is identify a suitable **setuid binary** to poison. The requirements are straightforward: the binary must be readable by the attacker's unprivileged user (which essentially all setuid binaries are, by design), it must be owned by root or another privileged user, and it must be something that will be executed by a privileged process in the near future.

The proof-of-concept (PoC) script pre-placed on the machine targets `/usr/bin/su`. It overwrites the cached copy of that binary with shellcode, after which any execution of `su` runs that shellcode with setuid root privileges. The complete operation takes a few seconds. The exploit used in this task is hosted at [GitHub](https://github.com/painoob/Copy-Fail-Exploit-CVE-2026-31431).

#### **Step 2 - Reading the Target Into the Page Cache**

Before the attacker can corrupt the page cache entry, that entry needs to exist. If the target binary hasn't been read recently, its pages may have been evicted from RAM. The attacker simply **opens and reads the target file** — a completely normal, unprivileged operation. This forces the kernel to load the binary's contents from disk into the page cache, where they will sit in RAM as a collection of page cache pages indexed by the binary's inode.

### **Step 3 - Triggering Execution**

With the page cache now poisoned, the attacker simply **invokes the target binary**. In the proof-of-concept, the attacker themselves runs `/usr/bin/su` — which now executes the attacker's tampered in-memory version rather than the legitimate code. Since `su` is a setuid binary owned by root, it begins execution with root's effective UID. The injected code runs before any authentication logic, spawns a shell, and the attacker has a root shell.

!![Image Description](/images/Pasted%20image%2020260511114823.png)

The script uses only Python standard library modules. The `os` module supplies `splice()` and `execve()`, `socket` provides the `AF_ALG` socket calls, and `zlib` is used for CRC calculations when building the authentication key blob. There are no pip packages and no compiled extensions. The script runs on any Python 3.10 or later installation. Ubuntu 24.04 ships Python 3.12, so `os.splice` is available out of the box.

At a high level, the script performs the following steps in sequence:

- Opens an `AF_ALG` socket bound to `authencesn(hmac(sha256),cbc(aes))`
- Calculates the target offset within `/usr/bin/su` where each shellcode chunk should land
- Constructs the AAD so that bytes 4-7 carry the shellcode value to write as `seqno_lo`
- Calls `splice()` to feed page cache pages from `/usr/bin/su` into the socket at the calculated offset
- Calls `recvmsg()` to trigger the AEAD decryption, at which point `authencesn` performs its scratch write and the shellcode bytes land in the page cache
- Repeats approximately 40 times to write successive 4-byte shellcode chunks
- Calls `os.execve("/usr/bin/su", ...)` so the kernel loads from the corrupted cache and the shellcode runs

---

## **Detection & Monitoring**

The exploitation window for Copy Fail is seconds wide. The on-disk file is never modified, the page cache is clean by the time cleanup runs, and the PoC uses only standard library calls that blend in with normal process activity. Filesystem monitoring, file integrity checks, and binary signature validation all miss this entirely.

What remains detectable is the process behaviour, specifically the sequence of system calls that no legitimate application produces at the volumes the exploit requires.

The window for finding evidence after the fact is very short. The `posix_fadvise(DONTNEED)` cleanup evicts the corrupted pages. By the time a responder opens the machine for triage, the page cache is clean, the disk is clean, and there are no modified binaries to find.

Detection for this class of vulnerability works by watching process behaviour at the time of exploitation, not by examining system state afterwards. Correlating `recvmsg()` calls on an `AF_ALG` file descriptor with `execve(/usr/bin/su)` in the same narrow time window is the indicator to build on. Filesystem forensics alone will not find this.

##### **MITRE ATT&CK Mapping**

| **Technique**                              | **MITRE ID** | **Primary Signal**                                             |
| ------------------------------------------ | ------------ | -------------------------------------------------------------- |
| Local Privilege Escalation via kernel flaw | T1068        | AF_ALG socket creation by unexpected process                   |
| Escape to Host from Container              | T1611        | Container ID in Falco alert and subsequent host-level activity |
| Setuid binary abuse                        | T1548.001    | `execve` of setuid binary after AF_ALG activity                |
| Indicator Removal via page eviction        | T1070        | `posix_fadvise(DONTNEED)` called on setuid binary              |

---

## **Mitigation Strategies**

The vulnerability lives in the `algif_aead` kernel module. Disabling that module removes the exploit's ability to open an `AF_ALG` socket bound to `authencesn`. The permanent fix is a kernel update to 6.18.22, 6.19.12, or 7.0 (or a vendor backport of the same fix), with the mainline patch landing as commit `a664bf3d603d` on 1 April 2026. Until your distribution ships a patched kernel, the `modprobe` blacklist is the recommended interim mitigation on Ubuntu and Debian systems.

#### **Step 1: Verify the Module Is Loadable**

First confirm that `algif_aead` is a loadable module on this system rather than being compiled directly into the kernel:

```bash
modinfo algif_aead
```

Module information should be returned, including the filename path. If the command returns module information, the `modprobe` blacklist approach will work.

#### **Step 2: Apply the Modprobe Blacklist**

```bash
echo "install algif_aead /bin/false" | sudo tee /etc/modprobe.d/disable-algif-aead.conf
sudo rmmod algif_aead 2>/dev/null || true
```

The first command writes a configuration file telling `modprobe` to run `/bin/false` instead of actually loading `algif_aead`. The second unloads the module if it is currently in memory. The `|| true` on the `rmmod` line prevents a harmless error from stopping the command if the module is already unloaded.

#### **Step 3: Verify the Block Is Active**

```bash
sudo modprobe algif_aead
```

This command should now return an error. The module load is blocked.

#### **Step 4: Confirm the PoC Fails**

Re-run the exploit script:

```bash
python3 /home/karen/exploit.py
```

The script should now fail at the very first step. The `socket(AF_ALG, ...)` call returns an error because the module cannot be loaded, and the rest of the exploit chain never executes. This is the expected outcome once the mitigation is applied.

**Warning:** The `modprobe` blacklist only works on distributions where `algif_aead` is a loadable kernel module. On RHEL, CentOS, and AlmaLinux, `algif_aead` is compiled directly into the kernel (`CONFIG_CRYPTO_USER_API_AEAD=y`). The `modprobe` configuration file is silently ignored on these systems because the module load never goes through `modprobe`. RHEL-family systems require the `grubby` approach.

```bash
sudo grubby --update-kernel=ALL --args="initcall_blacklist=algif_aead_init"
sudo reboot
```

Run `sudo grubby --info=ALL | grep initcall_blacklist` to verify the argument was applied before rebooting. The change can be reverted with `--remove-args="initcall_blacklist=algif_aead_init"` once the kernel patch has been applied.

#### **Patch Status at Disclosure**

The mainline fix was committed on 1 April 2026 (commit `a664bf3d603d`), nearly a month before public disclosure on 29 April. The fix reverts the 2017 in-place optimisation entirely, restoring separate `req->src` and `req->dst` scatterlists so that page cache pages from `splice()` can never end up in the output scatterlist. No vendor distribution had shipped a patched kernel on disclosure day. AlmaLinux was the first to release a patched kernel, on 1 May 2026. Ubuntu, Debian, RHEL, SUSE, and others followed in the days and weeks after.

The kernels affected span from 4.14 through 6.18.21 in the 6.18 series and 6.19.0 through 6.19.11 in the 6.19 series, covering every mainstream Linux distribution released between late 2017 and the April 2026 patch.

---

## **References and further reading**

- [TryHackMe Lab](https://tryhackme.com/room/cve202631341)
- [Xint Official Advisory](https://xint.io/blog/copy-fail-linux-distributions)
- [Copy.Fail](https://copy.fail/#copy-fail)
- [Exploit](https://github.com/painoob/Copy-Fail-Exploit-CVE-2026-31431)
- [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-31431)
- [# Modifying /usr/bin/su Without Writing to Disk - Copy Fail Explained - Jadi (Youtube)](https://www.youtube.com/watch?v=OftLQ1uPh4M)
