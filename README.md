# ufuncgraph

bpf(2)-based ftrace(1)-like function graph tracer for userspace processes.

Limits:

1. Only Works for Go programs for now;
2. `.symtab` ELF section is required, and `.debug_info` section is preferable;
3. The Go binary must be built using static linking;
3. Running on x86-64 little-endian Linux only;
4. Kernel version has to support bpf(2) and uprobe, and I developped it on 5.14.0;

# Example

Let's trace dockerd to see how it handles `docker stop`:

Type the command:

```bash
sudo ufuncgraph -d 1 ./bundles/binary-daemon/dockerd '!runtime.*' '!context.*' '!*vendor*' 'github.com/docker/docker/daemon.(*Daemon).containerStop(id=+0(+64(%rdi)):c256, name=+0(+200(%rdi)):c256, name_len=+208(%rdi):s32)'
```

Explanations:

1. `-d 1`: search the functions called by `github.com/docker/docker/daemon.(*Daemon).containerStop`, and only search for one layer;
2. `!runtime.*`: ignore the functions matching the wildcard `runtime.*`;
3. `!context.*`: ignore the functions matching the wildcard `context.*`;
4. `!*vendor*`: ignore the functions matching the wildcard `*vendor*`;
5. `github.com/docker/docker/daemon.(*Daemon).containerStop(id=+0(+64(%rdi)):c256, name=+0(+200(%rdi)):c256, name_len=+208(%rdi):s32)`: attach the function `github.com/docker/docker/daemon.(*Daemon).containerStop`, and fetch the arguments `id`, `name` and `name_len` using [Linux uprobe_tracer](https://docs.kernel.org/trace/uprobetracer.html)'s FETCHARGS syntax.

And will get the results:

![docker-stop-tracing](https://raw.githubusercontent.com/jschwinger233/ufuncgraph/master/assets/docker-stop-tracing.jpg)

# Use cases

1. Wall time profiling;
2. Execution flow observing;

## Wall time profiling case

Chinese version: https://roamresearch.com/#/app/FEZ/page/C-xt1C2M1

## Execution flow observing

Chinese version: https://roamresearch.com/#/app/FEZ/page/ya-t0xN8m
