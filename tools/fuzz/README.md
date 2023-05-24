# Fuzzing the Wi-SUN Linux Border Router

This tool is designed to fuzz the `wsbrd` daemon. To do so an additional
program `wsbrd-fuzz` is compiled, which wraps `wsbrd` and provides
additional options:

- `--capture` records all packets arriving at the UART and TUN interfaces, as
  well as keep track of time elapsed between packets. This data is saved to a
  file in a raw format, and is intended for use with `--replay`. Using
  `storage_prefix = -` is recommended to avoid using cache files.
- `--replay` replaces the regular UART input device with a file containing raw
  data (`-u` is ignored). To replay time delays, and TUN packets, some
  additional SPINEL commands have been added, which are only implemented in
  `wsbrd-fuzz`. The configuration used must be the same between capture and
  replay for it to work. This includes the config file, command line options,
  and release version.
- `--fuzz` ignores CRC checks for UART packets, stubs the RNG for large polls
  (which are generally seeds or keys for cryptographic purposes), and removes
  some SPINEL size checks to help the fuzzer. The NVM is also disabled as when
  using `storage_prefix = -`.
- `--capture-init` records the RCP initialization phase in a seperate file
  during capture. This helps the fuzzer explore the main loop rather than this
  restrictive phase.

While originally designed for fuzzing, these options can also be used as a
debug tool. The replay mode allows running a debugger several times without
reproductibility and time constraint present when debugging with real
hardware.

## Fuzzing with AFL++

### Installation

For better performance, installing LLVM is recommended. For Debian, official
scripts are available:

    wget https://apt.llvm.org/llvm.sh
    chmod +x llvm.sh
    sudo ./llvm.sh 12

The steps to install AFL++ are described in the official [GitHub
repository][1]. Here are the dependencies to install, using APT on
Debian based distributions:

    sudo apt-get install -y build-essential python3-dev automake cmake git
    flex bison libglib2.0-dev libpixman-1-dev python3-setuptools

[1]: https://github.com/AFLplusplus/AFLplusplus

Finally the repository can be cloned, built, and installed:

    git clone https://github.com/AFLplusplus/AFLplusplus
    cd AFLplusplus
    make
    sudo make install


### Gathering an input corpus

Before starting a fuzzing campain, some testcases need to be recorded. There
are some restrictions in what cases can be used. Namely, they must all use the
same configuration for both `wsbrd` and the RCP. That being because the fuzzer
will launch the program with the same arguments every time, which includes the
config file as well as the RCP initialization recording.

To record, use `wsbrd-fuzz` along with `--capture`, `--capture-init` and
`--fuzz`:

    wsbrd-fuzz -F wsbr.conf --capture=uart.raw --capture-init=init.raw --fuzz

Record several tests which cover different parts of the code, and gather the
results in a single directory which will be refered as `in/` going forward.

### Instrumenting the target

To retrieve coverage data, `wsbrd-fuzz` must be compiled with a special
compiler provided by AFL. To do so the option `-DCMAKE_C_COMPILER=afl-cc` can
be used when running CMake.

### Running the fuzzer

If everything is setup, the following command should start the campain:

    afl-fuzz -i in/ -o out/ -t 10000 -- \
        wsbrd-fuzz -F wsbr.conf --replay=init.raw --replay=@@ --fuzz

As mentioned, all replays will use the same config file as well as RCP init
recording. AFL will take care of substituting `@@` with its own testcases,
mutated from the content of `in/`.

Results will be stored in `out/`, and crashes in particular are located in
`out/default/crashes`.

## Implementation details

To be as little intrusive as possible with the main `wsbrd` code, the linker
option `--wrap` is used extensively.

### Time

`wsbrd` uses a single `timerfd` to handle timers, which is replaced with an
`eventfd` during replay for complete control. In replay mode, the SPINEL
command `SPINEL_CMD_REPLAY_TIMERS` will provide how many ticks to advance
before processing the next UART packet. UART reception is blocked until all
ticks are done, and timers are immediately retriggered after being processed
if there are pending ticks. This gets rid of the time contraint as several
minutes of capture can be replayed in less than a second.

### Entropy

To generate random numbers, `wsbrd` normally uses the system calls `getrandom`,
which does not provide any control over seeding. To have comparable behavior
between capture and replay, the random number generation has to be the same.
The libc `rand` function is thus used to provide a controlable source of
entropy, which is currently always seeded with `srand(0)`.

The library `mbedTLS` also relies on entropy polls. Wrapping `getrandom` is
enough to stub RNG, but time is also used during some cryptographic
procedures. Thus the function `time` is also wrapped to provide a constant
date. Thankfully this function is not used anywhere in `wsbrd` itself.
