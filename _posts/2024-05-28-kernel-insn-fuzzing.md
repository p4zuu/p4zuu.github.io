---
layout: post
title: Fuzzing the Linux kernel x86 instruction decoder and finding nothing
date: 2024-05-28
comment: true
---

# Context

For specific uses, the Linux kernel can
[decode x86 instructions](https://github.com/torvalds/linux/blob/master/arch/x86/lib/insn.c).
One of these uses is to handle #VC exceptions. VMM Communication Exception (or
#VC) was introduced with the confidential computing technologies (see
[15.35.5 #VC Exception in AMD manual](https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/programmer-references/24593.pdf)).
Some VM-exits (Non-Automatic Exits or NAE, cf
[Table 7: List of Supported Non-Automatic Events](https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/56421.pdf))
require the hypervisor to modify the guest's registers (eg. CPUID result is
stored in RAX, RBX, RCX and RDX). However, the hypervisor can't do this since
the registers state is encrypted (and integrity protected for SEV-SNP). So when
a NAE exits occurs in the guest, the CPU raises a #VC, handled by the guest
kernel by setting up a communication channel with the hypervisor, but this is
out of context. You can also refer to Tom's
[article](https://blog.freax13.de/cve/cve-2023-46813) that provides clear
explanations

However, to properly handle a #VC exception, the guest needs to find out which
NAE event raised the #VC. The CPU actually pushes the NAE exit code through the
error code on the kernel stack, so that the kernel knows which NAE exit
occurred. However, even when knowing the NAE exit code, it could not be enough
to fully handle the VM-exit, for example for an IN/OUT instruction, we need to
know what port (and value) is used in the instruction. Moreover, due to the
recent [AHOI attacks](https://ahoi-attacks.github.io/), we also need to
double-check that the instruction that raised the NAE-events matches the
CPU-provided error code.

For all these reasons, the guest kernel needs to decode the instructions pointed
by RIP when the exception occurred (RIP is aslo pushed on the stack by the CPU).
Once the guest decoded the instruction that raised the exception (eg. a CPUID),
it can properly handle the #VC with the appropriate handler (eg. by emulating
the instruction, or calling the hypervisor).

The funny part is, the instruction decoder is an attack surface. A guest _user_
can trigger a #VC (eg. CPUID can be executed from CPL-3), and user entry will
land in the kernel instruction decoder. Moreover, there is an intrinsic race
between when the #VC exception is raised, and when the exception handler fetches
the instructions for decoding. That opens a tiny window to an attacker to write
valid code raising a #VC, and just after to put an arbitrary 15-byte buffer
(maximum x86 instruction length) at the address where the #VC exception was
raised. Those 15 bytes will then be decoded by the kernel. Please note that this
attack scenario is only valid in an AMD SEV _guest_.

The problem is that the decoder is only called in an exception handler context,
not ideal for simple fuzzing, so I patched the kernel.

# Kernel patch

An easy way to fuzz the instruction decoder with Syzkaller is to expose the
decoding code to user with a new syscall:

```c
#include <asm/current.h>
#include <asm/insn.h>
#include <asm/vm86.h>
#include <linux/compiler_types.h>
#include <linux/mmu_context.h>
#include <linux/syscalls.h>

SYSCALL_DEFINE2(decode_insn, unsigned char __user *, user_insn_buf,
		struct insn __user *, decoded_insn)
{
	struct insn insn;
	unsigned char insn_buf[MAX_INSN_SIZE] = { 0 };
	int ret;

	if (copy_from_user(&insn_buf, user_insn_buf, sizeof(insn_buf)))
		return -EFAULT;

	ret = insn_decode(&insn, insn_buf, sizeof(insn_buf), INSN_MODE_64);
	if (ret < 0)
		goto out;

	if (copy_to_user(decoded_insn, &insn, sizeof(*decoded_insn)))
		return -EFAULT;

out:
	return ret;
}
```

This simply calls the
[insn_decode() API](https://github.com/torvalds/linux/blob/4a4be1ad3a6efea16c56615f31117590fd881358/arch/x86/lib/insn.c#L751),
with a user-provided buffer, and returns the `struct insn` result. You can find
the full patch
[here](https://github.com/p4zuu/kernel-insn-fuzzing/blob/main/patches/kernel.patch),
applied on c9c3395 ("Linux 6.2") (as recommended for Syzkaller setup). We now
want to define this new syscall in Syzkaller.

# Syzkaller patch

Since we created a new syscall, we need to add a new syscall definition in
syzkaller to enable fuzzing:

```
type insn_attr_t int32
type insn_byte_t int8
type insn_value_t int32

insn_field_union {
	value	insn_value_t
	bytes	array[insn_byte_t, 4]
}

insn_field {
	union	insn_field_union
	got	int8
	nbytes	int8
}

insn {
	prefixes		insn_field
	rex_prefix		insn_field
	vex_prifile		insn_field
	opcode			insn_field
	modrm			insn_field
	sib			insn_field
	displacement		insn_field
	u1			union1
	u2			union2
	emulate_prefix_size	int32
	attr			insn_attr_t
	opnd_bytes		int8
	addr_bytes		int8
	length			int8
	x86_64			int8

	kaddr			ptr[inout, insn_byte_t]
	end_kaddr		ptr[inout, insn_byte_t]
	next_byte		ptr[inout, insn_byte_t]
}

union1 {
	imm		insn_field
	moffset1	insn_field
	imm1		insn_field
}

union2 {
	moffset2	insn_field
	imm2		insn_field
}

decode_insn(buf buffer[in], i ptr[out, insn])
```

Please note that: I'm nore sure if this is fully correct, and we don't care
about the output `insn`, so I guess the whole syzlang `struct insn` definition
can be skipped to return a raw buffer.

You can find the complete Syzkaller patch
[here](https://github.com/p4zuu/kernel-insn-fuzzing/blob/main/patches/syzkaller.patch).
We can now follow the
[Syzkaller setup](https://github.com/google/syzkaller/blob/master/docs/linux/setup_ubuntu-host_qemu-vm_x86-64-kernel.md),
only enable the new `decode_insn` syscall, and start fuzzing.

# Results

The disapointing moment: I found nothing. Two main reasons for this:

- I run the fuzzer on my laptop, with limited resources. I got code coverage hit
  where I wanted (in arch/x86/lib/insn.c and arch/x86/lib/insn-eval.c), but not
  enough hits. So if you have more resources and time than me, please run this
  fuzzer again.
- The x86 decoder code is robust. It's using stack allocated buffers only,
  everyting is static, no runtime-decided sizes or indexes, etc.

In the end, it's a good news for Linux that no bug was found (it would have been
one more CVE), but this is not that simple. In #VC exception handling, the
critical part is not the decoding, it's the emulation. Emulating a user MMIO
request can be very dangerous. Previous bugs were found in the emulation code
(eg. CVE-2023-46813 and
[Tom's article](https://blog.freax13.de/cve/cve-2023-46813) once again). So this
is where to search.
