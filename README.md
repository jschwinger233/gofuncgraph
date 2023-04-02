# gofuncgraph

bpf(2)-based ftrace(1)-like function graph tracer for Golang processes.

Limits:

1. `.symtab` ELF section and `.(z)debug_info` is required;
2. Running on x86-64 little-endian Linux only;
4. Kernel version has to support bpf(2) and uprobe;


# Usage

```
   example: trace a specific function in etcd client "go.etcd.io/etcd/client/v3/concurrency.(*Mutex).tryAcquire"
     gofun ./bin 'go.etcd.io/etcd/client/v3/concurrency.(*Mutex).tryAcquire'

   example: trace all functions in etcd client
     gofun ./bin 'go.etcd.io/etcd/client/v3/*'

   example: trace a specific function and include runtime.chan* builtins
     gofun ./bin 'go.etcd.io/etcd/client/v3/concurrency.(*Mutex).tryAcquire' 'runtime.chan*'

   example: trace a specific function with some arguemnts
     gofun ./bin 'go.etcd.io/etcd/client/v3/concurrency.(*Mutex).tryAcquire(pfx=+0(+8(%ax)):c512, n_pfx=+16(%ax):u64, m.s.id=16(0(%ax)):u64)'
```

# Use cases

1. Wall time profiling;
2. Execution flow observing;
