---
layout: post
title: A simple use case of miri
date: 2023-12-15
comment: false
---

N1CTF had a very interesting Rust pwn challenge this year: [n1proxy](https://github.com/Nu1LCTF/n1ctf-2023/tree/main/pwn/n1proxy).
A TCP/UDP/UNIX proxy written in Rust with a non-obvious bug (to me at least). Disclaimer: I didn't solve this challenge.

The bug
-------

I invite the reader going through the author's writeup, but here is a recap of the vulnerable code:

```rust
fn my_recv_msg(fd: i32, recv_size: usize) -> Result<Vec<u8>> {
    let mut recv_iov = [iovec {
        iov_base: vec![0u8; recv_size].as_mut_ptr() as *mut _,
        iov_len: recv_size,
    }];

    // ...
    
    let res = unsafe { slice::from_raw_parts(recv_iov[0].iov_base as *const u8, recv_size) };
    Ok(res.to_vec())
}
```

The vector allocated to initialize the `iov_base` field of `recv_iov[0]` (which is an `iovec`) is actually `temporary`.
It's freed once its lifetime ends, which is at the end of `recv_iov` creation.
Afterward, `recv_iov[0].iov_base` becomes a `dangling pointer`, and any dereference is `undefined behavior`,
like `slice::from_raw_parts(recv_iov[0].iov_base as *const u8, ...`). In other terms, it's a use-after-free. 

Fortunately, [miri](https://github.com/rust-lang/miri) can find it.

miri
----

[miri](https://github.com/rust-lang/miri) is an experimental tool that can find some classes of `undefined bahaviors` in
Rust code, and it's awesome.

We can apply it to our use-case. Of course, now that we know where the bug is, it's easier to write a test and to run 
miri to spot the bug.

```rust
use libc::iovec;
use core::slice;

fn main() {
    let recv_size = 0x100;

    let recv_iov = [iovec {
        iov_base: vec![0u8; recv_size].as_mut_ptr() as *mut _,
        iov_len: recv_size,
    }];

    let _ = unsafe { slice::from_raw_parts(recv_iov[0].iov_base as *const u8, recv_size) };
}
```
Run:

```sh
cargo +nightly miri run
```

And admire:

```
error: Undefined Behavior: out-of-bounds pointer use: alloc838 has been freed, so this pointer is dangling
   --> /home/p4zuu/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/core/src/slice/raw.rs:102:9
    |
102 |         &*ptr::slice_from_raw_parts(data, len)
    |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ out-of-bounds pointer use: alloc838 has been freed, so this pointer is dangling
    |
    = help: this indicates a bug in the program: it performed an invalid operation, and caused Undefined Behavior
    = help: see https://doc.rust-lang.org/nightly/reference/behavior-considered-undefined.html for further information
help: alloc838 was allocated here:
   --> src/dangling_pointer_deref.rs:8:19
    |
8   |         iov_base: vec![0u8; recv_size].as_mut_ptr() as *mut _,
    |                   ^^^^^^^^^^^^^^^^^^^^
help: alloc838 was deallocated here:
   --> src/dangling_pointer_deref.rs:10:7
    |
10  |     }];
    |       ^
    = note: BACKTRACE (of the first span):
    = note: inside `std::slice::from_raw_parts::<'_, u8>` at /home/p4zuu/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/library/core/src/slice/raw.rs:102:9: 102:47
note: inside `main`
   --> src/dangling_pointer_deref.rs:12:22
    |
12  |     let _ = unsafe { slice::from_raw_parts(recv_iov[0].iov_base as *const u8, recv_size) };
    |                      ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    = note: this error originates in the macro `vec` (in Nightly builds, run with -Z macro-backtrace for more info)

note: some details are omitted, run with `MIRIFLAGS=-Zmiri-backtrace=full` for a verbose backtrace

error: aborting due to 1 previous error; 1 warning emitted
```

miri correctly reports that the temporary vector is allocated when initializing `recv_iov`, freed when we go out of 
this context, and then used in `slice::from_raw_parts(recv_iov[0].iov_base as *const u8, ...)`.
If you wondered, this code perfectly builds, without any complain.

Note for next time, running miri to suspicious code can save hours of code review.
