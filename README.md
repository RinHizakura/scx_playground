# scx_playground

This is a playground to develop a BPF-extensible scheduler(sched_ext) on Linux. It
aims to provide friendly example for everyone to build their custumized scheduler.

For simplicity, we assume that the extensible scheduler always builds with the
kernel source codes that it will run on later. We also assume that there's no
requirement for cross-compilation. Base on the assumptions, we can purposely
design a simple Makefile which is friendly for user to take a glance and understand
the compilation flow easily.

## How to play with scx?

Under the assumption above, first you need to clone the Linux kernel with
verison >= 6.13 and build it. Please note that the version of toolchain and the
configuration for Linux is also restricted. Take a look at
[this page](https://github.com/sched-ext/sched_ext/tree/sched_ext/tools/sched_ext)
for the details.

After compiling the kernel, you just need to put this project under the path
`tools/sched_ext` and run `make`. Then you obtain a binary `sched` under `build`
directory which is able to plug your custumized scheduler by executing it!

## Reference

If you can read Chinese, this [article](https://hackmd.io/@RinHizakura/r1uSVAWwp) is
recommanded to be read before trying this project.
