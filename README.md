# gofuncgraph

bpf(2)-based ftrace(1)-like function graph tracer for Golang processes.

Limits:

1. `.symtab` ELF section and `.(z)debug_info` is required;
2. Running on x86-64 little-endian Linux only;
4. Kernel version has to support bpf(2) and uprobe;


# Usage & Example

## Issue Description

Let's debug a demo project under the [exmaple/](https://github.com/jschwinger233/gofuncgraph/tree/main/example)!

There is a simple and small HTTP server binding 8080 port, and we can access its `/bar` uri:

```shell
$ curl localhost:8080/bar
Hello, "/bar"
```

The problem here is, this HTTP API doesn't seem stable in terms of performance. Sometime the latency even goes as long as nearly one second:

```
$ time curl localhost:8080/bar
Hello, "/bar"
real	0m0.714s
user	0m0.005s
sys	0m0.000s
```

Let's investigate this issue using `gofuncgraph`.

## Investigation using gofuncgraph

We must find the HTTP handler for `/bar`, which is `handleBar` function. This requires some basic source code reading, luckily that's the only information we need from source.

### First run

Let's confirm it's the HTTP handler responsible for slow reply:

```
$ sudo gofuncgraph --uprobe-wildcards '*handleBar' ./example '*handleBar'
found 3 uprobes, large number of uprobes (>1000) need long time for attaching and detaching, continue? [Y/n]
y
INFO[0001] start tracing

18 15:48:05.4114           main.handleBar() { net/http.HandlerFunc.ServeHTTP+47 /home/gray/.gvm/gos/go1.20/src/net/http/server.go:2122
18 15:48:05.9347 000.5233  } main.handleBar+192 /home/gray/src/github.com/jschwinger233/gofuncgraph/example/main.go:20
```

The tracing command has the same tailing argument `*handleBar` as `--uprobe-wildcards`, I'll explain that later.

`*handleBar` is a wildcard to match the full symbol `main.handleBar`. We can always specify a full symbol rather than a wildcard, I was just too lazy to type.

The output showed the function `main.handleBar` returned in 0.5 second, which confirmed it was this function causing the unexpected latency.

### Second run

It is reasonable to suspect `net/http` to have caused latency, so let's measure the time cost for `net/http`.

```
$ sudo gofuncgraph --uprobe-wildcards 'net/http*' ./example '*handleBar'
found 1637 uprobes, large number of uprobes (>1000) need long time for attaching and detaching, continue? [Y/n]
y
INFO[0001] start tracing

18 16:01:17.0181           main.handleBar() { net/http.HandlerFunc.ServeHTTP+47 /home/gray/.gvm/gos/go1.20/src/net/http/server.go:2122
18 16:01:17.7443             net/http.(*response).Write() { fmt.Fprintf+155 /home/gray/.gvm/gos/go1.20/src/fmt/print.go:225
18 16:01:17.7443               net/http.(*response).write() { net/http.(*response).Write+48 /home/gray/.gvm/gos/go1.20/src/net/http/server.go:1594
18 16:01:17.7443                 net/http.(*conn).hijacked() { net/http.(*response).write+105 /home/gray/.gvm/gos/go1.20/src/net/http/server.go:1603
18 16:01:17.7443                   net/http.(*conn).hijacked.func1() { net/http.(*conn).hijacked+167 /home/gray/.gvm/gos/go1.20/src/net/http/server.go:312
18 16:01:17.7443 000.0000          } net/http.(*conn).hijacked.func1+47 /home/gray/.gvm/gos/go1.20/src/net/http/server.go:311
18 16:01:17.7443 000.0000        } net/http.(*conn).hijacked+181 /home/gray/.gvm/gos/go1.20/src/net/http/server.go:312
18 16:01:17.7443                 net/http.(*response).WriteHeader() { net/http.(*response).write+345 /home/gray/.gvm/gos/go1.20/src/net/http/server.go:1622
18 16:01:17.7444                   net/http.(*conn).hijacked() { net/http.(*response).WriteHeader+69 /home/gray/.gvm/gos/go1.20/src/net/http/server.go:1136
18 16:01:17.7444                     net/http.(*conn).hijacked.func1() { net/http.(*conn).hijacked+167 /home/gray/.gvm/gos/go1.20/src/net/http/server.go:312
18 16:01:17.7444 000.0000            } net/http.(*conn).hijacked.func1+47 /home/gray/.gvm/gos/go1.20/src/net/http/server.go:311
18 16:01:17.7444 000.0000          } net/http.(*conn).hijacked+181 /home/gray/.gvm/gos/go1.20/src/net/http/server.go:312
18 16:01:17.7444 000.0000        } net/http.(*response).WriteHeader+1786 /home/gray/.gvm/gos/go1.20/src/net/http/server.go:1183
18 16:01:17.7444 000.0001      } net/http.(*response).write+557 /home/gray/.gvm/gos/go1.20/src/net/http/server.go:1636
18 16:01:17.7444 000.0001    } net/http.(*response).Write+57 /home/gray/.gvm/gos/go1.20/src/net/http/server.go:1594
18 16:01:17.7444 000.7263  } main.handleBar+192 /home/gray/src/github.com/jschwinger233/gofuncgraph/example/main.go:20
```

There were multiple blocks displayed, in which only the one for `main.handleBar` is of our interests, as I showed above.

The `--uprobe-wildcards` in the command was changed to `net/http*`, so we can see the their invocation situations.

Generally, the wildcard in the tailing arguments are the ones we really care, let's call them "target functions"; on the other hand, `--uprobe-wildcards` means **we want to see how these functions are called by target functions**.

Getting back to the command, `gofuncgraph --uprobe-wildcards 'net/http*' ./example '*handleBar'` indicates that **we want to see how those net/http functions are called inside the main.handleBar**.

Look at the output, `main.handleBar` cost 0.7s, while `net/http.(*response).Write` cost less then 0.0001s. The problem isn't on the golang's http library!

### Third run

We'll have to look at the assembly code of `main.handleBar`:

```
(gdb) disas/m 'main.handleBar'
Dump of assembler code for function main.handleBar:
17	func handleBar(w http.ResponseWriter, r *http.Request) {
   0x00000000006178c0 <+0>:	cmp    0x10(%r14),%rsp
   0x00000000006178c4 <+4>:	jbe    0x617981 <main.handleBar+193>
   0x00000000006178ca <+10>:	sub    $0x58,%rsp
   0x00000000006178ce <+14>:	mov    %rbp,0x50(%rsp)
   0x00000000006178d3 <+19>:	lea    0x50(%rsp),%rbp
   0x00000000006178d8 <+24>:	mov    %rax,0x60(%rsp)
   0x00000000006178dd <+29>:	mov    %rcx,0x70(%rsp)
   0x0000000000617981 <+193>:	mov    %rax,0x8(%rsp)
   0x0000000000617986 <+198>:	mov    %rbx,0x10(%rsp)
   0x000000000061798b <+203>:	mov    %rcx,0x18(%rsp)
   0x0000000000617990 <+208>:	call   0x4645e0 <runtime.morestack_noctxt>
   0x0000000000617995 <+213>:	mov    0x8(%rsp),%rax
   0x000000000061799a <+218>:	mov    0x10(%rsp),%rbx
   0x000000000061799f <+223>:	mov    0x18(%rsp),%rcx
   0x00000000006179a4 <+228>:	jmp    0x6178c0 <main.handleBar>

18		log.Debug("received request for /bar")
   0x00000000006178ec <+44>:	xor    %edi,%edi
   0x00000000006178ee <+46>:	mov    %rdi,%rsi
   0x00000000006178f1 <+49>:	lea    0x67bdc(%rip),%rax        # 0x67f4d4
   0x00000000006178f8 <+56>:	mov    $0x19,%ebx
   0x00000000006178fd <+61>:	xor    %ecx,%ecx
   0x00000000006178ff <+63>:	nop
   0x0000000000617900 <+64>:	call   0x6177a0 <github.com/jschwinger233/gofuncgraph/example/internal/log.Debug>

19		fmt.Fprintf(w, "Hello, %q", html.EscapeString(r.URL.Path))
```

We can tell from gdb's output that there is a `log.Debug` prior to net/http functions.

Let's trace that suspicious log statement.

```
$ sudo gofuncgraph --uprobe-wildcards 'net/http*' --uprobe-wildcards '*gofuncgraph/example/internal/log*' ./example '*handleBar'
found 1639 uprobes, large number of uprobes (>1000) need long time for attaching and detaching, continue? [Y/n]
y
INFO[0002] start tracing

18 16:21:55.2553           main.handleBar() { net/http.HandlerFunc.ServeHTTP+47 /home/gray/.gvm/gos/go1.20/src/net/http/server.go:2122
18 16:21:55.2553             github.com/jschwinger233/gofuncgraph/example/internal/log.Debug() { main.handleBar+69 /home/gray/src/github.com/jschwinger233/gofuncgraph/example/main.go:18
18 16:21:55.6098 000.3545    } github.com/jschwinger233/gofuncgraph/example/internal/log.Debug+58 /home/gray/src/github.com/jschwinger233/gofuncgraph/example/internal/log/log.go:11
18 16:21:55.6098             net/http.(*response).Write() { fmt.Fprintf+155 /home/gray/.gvm/gos/go1.20/src/fmt/print.go:225
18 16:21:55.6098               net/http.(*response).write() { net/http.(*response).Write+48 /home/gray/.gvm/gos/go1.20/src/net/http/server.go:1594
18 16:21:55.6098                 net/http.(*conn).hijacked() { net/http.(*response).write+105 /home/gray/.gvm/gos/go1.20/src/net/http/server.go:1603
18 16:21:55.6098                   net/http.(*conn).hijacked.func1() { net/http.(*conn).hijacked+167 /home/gray/.gvm/gos/go1.20/src/net/http/server.go:312
18 16:21:55.6099 000.0000          } net/http.(*conn).hijacked.func1+47 /home/gray/.gvm/gos/go1.20/src/net/http/server.go:311
18 16:21:55.6099 000.0000        } net/http.(*conn).hijacked+181 /home/gray/.gvm/gos/go1.20/src/net/http/server.go:312
18 16:21:55.6099                 net/http.(*response).WriteHeader() { net/http.(*response).write+345 /home/gray/.gvm/gos/go1.20/src/net/http/server.go:1622
18 16:21:55.6099                   net/http.(*conn).hijacked() { net/http.(*response).WriteHeader+69 /home/gray/.gvm/gos/go1.20/src/net/http/server.go:1136
18 16:21:55.6099                     net/http.(*conn).hijacked.func1() { net/http.(*conn).hijacked+167 /home/gray/.gvm/gos/go1.20/src/net/http/server.go:312
18 16:21:55.6099 000.0000            } net/http.(*conn).hijacked.func1+47 /home/gray/.gvm/gos/go1.20/src/net/http/server.go:311
18 16:21:55.6099 000.0000          } net/http.(*conn).hijacked+181 /home/gray/.gvm/gos/go1.20/src/net/http/server.go:312
18 16:21:55.6099 000.0000        } net/http.(*response).WriteHeader+1786 /home/gray/.gvm/gos/go1.20/src/net/http/server.go:1183
18 16:21:55.6099 000.0000      } net/http.(*response).write+557 /home/gray/.gvm/gos/go1.20/src/net/http/server.go:1636
18 16:21:55.6099 000.0001    } net/http.(*response).Write+57 /home/gray/.gvm/gos/go1.20/src/net/http/server.go:1594
18 16:21:55.6099 000.3546  } main.handleBar+192 /home/gray/src/github.com/jschwinger233/gofuncgraph/example/main.go:20
```

No need to replace the `net/http*`, jsut adding a new `--uprobe-wildcards '*gofuncgraph/example/internal/log*'` will do.

The output clearly showed it was this internal `log.Debug` dragging down the HTTP handle.

Alright, I think that's enough to close this issue. If you inspect how `log.Debug` is implemented, you'll find a `time.Sleep()` inside to stimulate the real world random latency.

# Use cases

1. Wall time profiling;
2. Execution flow observing;
