# scx_playground

This is a playground to develop a BPF-extensible scheduler(sched_ext) on Linux. It
aims to provide friendly framework for everyone to build their scheduler with their
own implementation!

For simplicity, we assume that the extensible scheduler always builds with the
kernel source codes that it will run on later. We also assume that there's no
requirement for cross-compilation. These assumptions purposely lead to a simple
Makefile which should be more friendly for reader to take a glance and understand
the compilation flow easily. Once you understand the minimalist Makefile to build
the sched_ext, extending it for advanced requirement should not be a hard problem

## How to play with scx?

Under the assumption above, first you need to clone the kernel that support extensible
scheduler([sched_ext](https://github.com/sched-ext/sched_ext/tree/sched_ext)) and build it.
The version of toolchain and the configuration for kernel is restricted. Please take
a look at [this page](https://github.com/sched-ext/sched_ext/tree/sched_ext/tools/sched_ext)
for the details.

After compiling the kernel, you just need to put this project under the path
`tools/sched_ext` and run `make`. Then you obtain a binary `sched` under `build`
directory which is able to plug your custumized scheduler by executing it!

## Reference

If you can read Chinese, this [article](https://hackmd.io/@RinHizakura/r1uSVAWwp) is
recommanded to be read before trying this project.
