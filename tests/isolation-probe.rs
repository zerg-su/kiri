//! Tiny, static test executable. It contains no host data or runtime dependency.
use std::ffi::{c_int, c_long};
unsafe extern "C" {
    fn syscall(number: c_long, ...) -> c_long;
    fn __errno_location() -> *mut c_int;
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    #[cfg(target_arch = "aarch64")]
    let numbers = (173, 155, 198, 97, 167);
    #[cfg(target_arch = "x86_64")]
    let numbers = (110, 121, 41, 272, 157);
    let (nr, arg, arg2, expected) = match args.get(1).map(String::as_str) {
        Some("getppid") => (numbers.0, 0, 0, args[2].parse::<i32>().unwrap()),
        Some("getpgid") => (
            numbers.1,
            args[2].parse::<u64>().unwrap(),
            0,
            args[3].parse::<i32>().unwrap(),
        ),
        Some("vsock") => (numbers.2, 40, 1, 97), // AF_VSOCK, SOCK_STREAM: EAFNOSUPPORT
        Some("uring") => (425, 1, 0, 1), // io_uring_setup: EPERM before dereferencing params
        Some("userns") => (numbers.3, 0x1000_0000, 0, 0),
        Some("nnp") => (numbers.4, 39, 0, 0), // PR_GET_NO_NEW_PRIVS
        _ => panic!("expected getppid/getpgid/vsock/uring/userns/nnp"),
    };
    let result = unsafe {
        syscall(
            nr,
            arg as c_long,
            arg2 as c_long,
            0 as c_long,
            0 as c_long,
            0 as c_long,
        )
    };
    let errno = if result == -1 {
        unsafe { *__errno_location() }
    } else {
        0
    };
    println!("result={result} errno={errno}");
    assert_eq!(errno, expected);
    if args[1] == "nnp" {
        assert_eq!(
            result, 0,
            "custom profiles must preserve setuid/sudo unless no-new-privileges was requested"
        );
    }
}
