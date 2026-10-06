# ShadowVPN 0.7.0 — 可选 TCP 载波 + 可关闭加密

基于上游 `madeye/shadowvpn`（UDP PSK 用户态 VPN，shadowsocks AEAD UDP 线格式）改造。

## 本次新增的两个可配置项

| 配置项 | 取值 | 默认 | 说明 |
| --- | --- | --- | --- |
| `transport` | `udp` / `tcp` | `udp` | 载波协议。UDP 保留原行为；TCP 走带 2 字节长度前缀的字节流 |
| `cipher` | `aes-128-gcm` / `aes-256-gcm` / `chacha20-poly1305` / `none` | `chacha20-poly1305` | `none` 表示不加密，明文透传，且不再要求 `password` |

两项互相独立：`udp + none`、`tcp + aes-256-gcm` 等四种组合都可用。
**两端必须配置一致**——协议不协商，配错就是一个「解不开包」的黑洞。

用法：

```bash
# 服务端：TCP + 不加密
shadowvpn-server -l 0.0.0.0:8388 -t tcp -m none --tun-ip 10.9.0.1 --peer-ip 10.9.0.2

# 客户端：TCP + ChaCha20
shadowvpn-client -s vpn.example.com:8388 -t tcp -m chacha20-poly1305 -k 'pw'
```

JSON 配置：

```json
{
  "server": "vpn.example.com:8388",
  "password": "correct horse battery staple",
  "cipher": "chacha20-poly1305",
  "transport": "tcp"
}
```

## TCP 载波：为什么必须加长度前缀

UDP 的一个数据报就是一个帧，内核保证边界；TCP 是字节流，没有边界。
因此 TCP 上每帧前加 2 字节大端长度，长度覆盖的正是「UDP 本会发送的那一份字节」：

```text
[ len: u16 big-endian ] ++ [ obfs 头(可选) ++ salt ++ AEAD(密文 ++ tag) ]
```

- 单帧上限 65535 字节；更大的包被丢弃并记录日志（读取时会把超长帧排空，保证后续帧不错位）
- 长度前缀本身不加密不认证：注入者只能伪造一个超大的 `len` 迫使断连，改不了帧内容（AEAD tag 会拒）
- 服务端每个客户端一条长连接，客户端断线后自动重连（最多 10 次，之后退出交给 supervisor 重启）
- 所有连接都开启 `TCP_NODELAY`：隧道里是小包流，Nagle 合并会引入额外延迟

## 改动清单

### 新增文件
- `src/transport.rs` — `Transport` 枚举（`Udp` / `TcpServer` / `TcpClient`）、`TcpHub`（多连接聚合为单一收包源）、`TcpClient`（单连接 + 监督任务自动重连）、TCP 分帧读写

### 修改文件
- `src/net.rs` — 新增 `bind_tcp_listener` / `connect_tcp_stream` / `configure_tcp_stream`（含 `TCP_NODELAY` 与缓冲区调优）
- `src/crypto.rs` — `Cipher` 增加 `None` 变体（别名 `plain` / `plaintext`），`key_len`/`salt_len` 为 0；`encrypt_packet` / `decrypt_packet` 在 `None` 下直通；`Cipher::is_none()`
- `src/protocol.rs` — `crypto_overhead` 对 `none` 返回 0；新增 `TCP_LEN_PREFIX` / `MAX_TCP_FRAME` / `max_tcp_frame_size`
- `src/config.rs` — 新增 `TransportKind`（`DEFAULT_TRANSPORT = Udp`）、`FileConfig.transport`、`ServerConfig.transport`、`ClientConfig.transport`、CLI `-t/--transport`、`resolve_transport`；`resolve_crypto` 在 `none` 时不再要求 password
- `src/bin/server.rs` — 绑定逻辑按 `cfg.transport` 分支；两个转发循环改用 `Arc<Transport>`；启动横幅显示载波与「加密已关闭」告警
- `src/bin/client.rs` — 同样切换；`transport` 建立仍在 TUN 起来之前（Windows 源地址选择问题）
- `src/lib.rs` — 注册 `pub mod transport`
- `README.md`、`docs/reference/configuration.md`、`docs/reference/wire-protocol.md` — 文档同步
- `Cargo.toml` — 版本 0.7.0

### 未改动
TUN 设备、NAT/地址分配、mesh 子网路由、Magic DNS、策略路由、obfs 混淆等模块——它们工作在帧之上，与载波和加密方式无关，因此一行未动。

## 已知限制

1. **TCP 上的队头阻塞**：TCP 按序交付，一个丢包会阻塞后续所有 IP 包。隧道内再跑 TCP（即 TCP-in-TCP）时，丢包恢复会明显劣化。
2. **`cipher: none` 无任何保护**：明文、无认证、可被注入。仅用于可信链路、性能基线测量或调试。
3. **无协议协商**：两端 `transport` / `cipher` 配错不会报错提示，只会表现为大量「解包失败」日志。
4. **`cipher: none` 下 obfs 仍可叠加**，但 obfs 只是整形不是加密，不提供机密性。
5. **TCP 单帧上限 65535**：TUN MTU 接近 64 KiB 且开启加密时，个别包会被丢弃，建议 MTU ≤ 1400。

## 性能修正：从 ~15 Mbps 到 500 Mbps+

### 为什么只有 15 Mbps

单条 TCP 连接的吞吐上限约等于 `接收窗口 / RTT`。实测 15 Mbps 的根因是**客户端发起
连接的 socket 没有设置缓冲区**：`bind_tcp_listener` 设了 4 MiB，但
`connect_tcp_stream` 走的是 `TcpStream::connect`，用的是系统默认（常为几十 KB 到
几百 KB）。在 RTT 较高的路径上，窗口被压到几十 KB → 吞吐就被锁死在 15 Mbps 量级。
链路带宽再大也没用，这是协议层的窗口限制，不是 CPU 或带宽瓶颈。

### 四项修正

1. **修好 socket 缓冲区（根因）**
   `connect_tcp_stream` 改为用 `socket2` 手工建 socket，**在 connect 之前**设置
   4 MiB 收发缓冲区（connect 后再设对已建立的连接无效），非阻塞 connect + 等
   `writable()`。`configure_tcp_stream` 也对 accepted/connected 的流补设一次。
   `net.rs` 新增 `TCP_BUFFER_BYTES = 4 MiB`。

2. **批量 I/O**
   - 读：一次 `read` 拿到的数据可能含多个帧，`FrameReader` 循环解析，不再一帧一 syscall。
   - 写：`tcp_write_loop` 用 `try_recv` 把队列里待发的帧合并成一次 `write_all`，
     小包场景 syscall 数量下降一个数量级。

3. **多子流并行（`--subflows N`，默认 4，最大 16）**
   单连接的窗口上限无法靠调参突破，所以开 N 条连接并行。客户端按内层 IP 五元组
   哈希（`flow_hash`，FNV-1a）选子流——**在加密前对明文计算**，因为 AEAD 的随机
   salt 会让每条密文看起来毫无关联。同一条内层连接恒定落在同一子流，保证顺序；
   不同连接分散到各子流，共享 N 份窗口。服务端无需配置：它按同样的哈希在学到的
   多个 endpoint 中挑选，回程流量同样分散。keepalive 广播到所有子流，避免空闲的
   那条被对端回收。

4. **服务端多 endpoint 路由**
   `ClientEntry` 从单 `peer` 改为 `peers: Vec<SocketAddr>`（上限 16），`learn` 追加、
   `lookup` 按 `flow % peers.len()` 挑选、`unlearn` 仅在最后一个 endpoint 离开时才
   删除映射。

### 为什么没有用 yamux

yamux 在**单条 TCP** 上多路复用多个逻辑流。它能减少连接数和握手开销，但**无法突
破单连接的窗口/RTT 上限**——所有流共享同一个拥塞窗口和同一条按序交付的管道，吞吐
上限不变，队头阻塞也依旧。要达到 500 Mbps，需要的是多条物理连接各自的窗口，即
这里的 subflows 方案。两者并不冲突：若未来既要少连接又要高吞吐，可在每条子流上再
跑 yamux，但那会增加复杂度而不提升上限。

### 预期效果

| 场景 | 修正前 | 修正后 |
| --- | --- | --- |
| 高 RTT 路径，单连接 | ~15 Mbps | 窗口 4 MiB 后按 `窗口/RTT` 提升 |
| 4 子流 | — | 约 4 倍单连接吞吐 |
| 8–16 子流 | — | 接近链路或 CPU 上限 |

实际值取决于 RTT、丢包率与 CPU（AEAD 加解密是单核密集）。建议先用
`--subflows 4` 测，再逐步加到 8/16 观察收益递减点。

## UDP 封装进 TCP 隧道后慢（~12 Mbps）的原因与修正

### 先纠正上一轮的一个错误判断

上一轮我判断"QUIC 会把乱序当成丢包"，据此把 UDP 设计成"钉在一条子流、仅在积压时溢出"。
**这个判断是错的**：UDP 从不保证顺序，QUIC 有 packet number 和 ACK range，天生能消化
乱序。真正杀死内层 UDP 的不是乱序，而是**队头阻塞造成的整条流停滞（blackout）**。

### 真正的原因：单条 TCP 连接会整体停滞

一条 TCP 连接是**作为一个整体 stall 的**：丢一个 segment，其后所有已到达的数据都被内核
扣住等重传，持续一个 RTT，超时的话更久。

- **内层 TCP 不怕这个。** 它本身就有序、自带重传，外层 stall 只是"链路变慢了"，等一会
  继续按自己的窗口发，恢复很快。所以 TCP 流量拿到 subflows 后提升明显。
- **内层 UDP 怕得要命。** UDP 没有重传定时器，一条 UDP 流若被钉在单条子流上，就是
  **整整停滞一个 stall 的时长，一个包都收不到**。QUIC 这类会估计 RTT 的协议把这件事
  解读为链路灾难：PTO（probe timeout）触发，拥塞窗口被打到最小值，之后要靠许多个
  往返才能爬回来——这正是"稳定 12 Mbps 上不去"的表现形态。

所以 **`--subflows N` 对单条 UDP 流的收益，在"钉死 + 溢出"的策略下几乎为零**：绝大多数
时间它仍只在一条子流上跑，该 stall 的时候照样 stall。

### 修正：按内层协议采取相反的策略

`transport::pick_subflow()` 统一决策：

| 内层协议 | 放置策略 | 理由 |
| --- | --- | --- |
| TCP（`proto == 6`） | **钉死**在 hash 选中的子流 | 有序、自带丢包恢复；乱序会引发 dup ACK 与虚假快速重传，代价大于并行收益 |
| UDP 及其他 | **打散**到所有健康的子流 | 无重传定时器，必须避免整流停滞；UDP 容忍乱序 |

打散的实现要点：

1. **在最小 backlog 的子流集合中按 `hash ^ spin` 选取**。`spin` 每包递增——这是关键。
   如果只用 `hash`，一条 UDP 流的 hash 恒定，会永远落在同一个 index 上，等于没打散；
   混入每包变化的 `spin` 才能让**单条流**的包真正轮转开。
2. **排开正在积压的子流**：`backlog = TCP_CHANNEL_DEPTH - tx.capacity()`，重连中（无
   sender）视为 ∞。有了 `TCP_NOTSENT_LOWAT = 32 KiB`，write 会在内核未发送字节超限
   时阻塞，backlog 因此是真实的拥塞信号，积压的子流会被自动绕开。
3. 两端都这么做：客户端 `TcpClient::send_hint`，服务端 `TcpHub::queue`。UDP 打散
   **不需要两端对应**（UDP 无顺序要求），所以服务端学到的 endpoint 顺序与客户端的
   subflow index 不一致也无所谓。
4. 控制报文与 keepalive 仍按 `ordered = true` 处理（`send_on` / `send_all`），保持
   路径稳定。

### 为什么这能解决，而不是"更乱了"

把一条 UDP 流分散到 N 条子流后，某条子流 stall 时只有 `1/N` 的包被卡住，其余继续到达。
内层协议看到的是**延迟温和上升**而非**完全黑屏**，QUIC 的 PTO 不会触发，拥塞窗口不会
崩到最小。队头阻塞从"整流停摆"降级为"局部变慢"——这正是多子流对 UDP 唯一有意义的
价值。

### 配套保留的两项（上一轮已加，仍然必要）

- **BBR 拥塞控制**（Linux，`TCP_CONGESTION`）：CUBIC 在深缓冲隧道上会周期性砍半窗口。
- **`TCP_NOTSENT_LOWAT = 32 KiB`**：压浅内核队列，削掉 bufferbloat 延迟，并让 backlog
  信号真实可信。

### 预期效果与调优

| 场景 | 上一版 | 修正后 |
| --- | --- | --- |
| 内层 TCP 多连接 | 已随 subflows 提升 | 不变（仍钉死） |
| 单条 UDP / QUIC 流 | ~12 Mbps（实际钉在单子流） | 随 subflows 近似线性提升 |
| 子流 stall 时 | 整条 UDP 流停摆 | 仅 1/N 包延迟上升 |

QUIC 是单五元组，**只有打散才能让它吃到多子流的带宽**。建议 `--subflows 8` 起步测，
用 `iperf3 -u -b 200M` 和实际 HTTP/3 下载对照。若确实遇到乱序敏感的应用（极少），
可把 `spin` 改为按批次递增（如 `counter >> 3`）以降低乱序粒度。

## 内层 TCP 流在 subflows=8/16 下仍只有 ~50 Mbps 的原因与修正

### 根因：`SO_RCVBUF` 是个吞吐陷阱

上一版我"修好 socket 缓冲区"的方式是调用 `set_recv_buffer_size(4 MiB)`。**这恰恰是
50 Mbps 的直接原因**——Linux 上有两个行为叠加：

1. `SO_RCVBUF` 会被 clamp 到 `net.core.rmem_max`，**默认 208 KiB**。请求 4 MiB，实际
   只拿到 208 KiB。
2. **只要调用了 `SO_RCVBUF`，内核就会置 `SOCK_RCVBUF_LOCK`，从而禁用 TCP 接收窗口
   自动调优**。自动调优本来能把窗口增长到 `net.ipv4.tcp_rmem[2]`（默认约 6 MiB）。

两者叠加 = 窗口锁死在约 416 KiB。按 `window / RTT` 计算，66 ms RTT 下：

```
416 KiB × 8 / 0.066 s ≈ 50 Mbps
```

**与你实测的 50 Mbps 精确吻合。** 这也解释了为什么 subflows 从 8 加到 16 没用：每条
子流的窗口都被锁死，加多少条都一样。

### 修正（三项）

1. **改用 `SO_RCVBUFFORCE`**（`=33`，需 `CAP_NET_ADMIN`，VPN 通常以 root 运行）
   绕过 `rmem_max` 的 clamp，拿到完整的 4 MiB 窗口。
2. **失败时故意不设 `SO_RCVBUF`**（关键）
   若没有 `CAP_NET_ADMIN`，**什么都不设**，让内核自动调优继续工作（上限 6 MiB，是
   208 KiB 的 ~30 倍）。绝不能回退到普通 `SO_RCVBUF`——那会把窗口锁在 208 KiB，
   比不设还慢一个数量级。
   发送缓冲无自动调优可失去，故 `SO_SNDBUFFORCE` 失败时回退普通 `SO_SNDBUF` 即可。
3. **启动时回读并告警**
   读回 `SO_RCVBUF`（Linux 返回 `sk_rcvbuf`，是设定值的 2 倍），若低于请求值就
   warn，并给出按每 100 ms RTT 折算的单子流上限，让"窗口不够"这件事显式可见，
   而不是表现为莫名的慢。

同时把 `TCP_NOTSENT_LOWAT` 从 32 KiB 提到 **512 KiB**：32 KiB 会让写端在管道未填满时
就被判定不可写，在高 BDP 路径上直接限流。

另外为有序流加了回退：pinned 子流断连重连中时，改投最空闲的存活子流——重连本身
已经造成乱序，此时丢弃全部包不如换条路走。

### 期望值：单条内层 TCP 流的天花板

内层 TCP 被钉在单条子流上（保证有序），所以单流上限 = 该子流的 `window / RTT`。
窗口 4 MiB 时：

| RTT | 单条内层 TCP 流 |
| --- | --- |
| 10 ms | ~3.3 Gbps |
| 30 ms | ~1.1 Gbps |
| 66 ms | ~500 Mbps |
| 150 ms | ~220 Mbps |

所以 **66 ms RTT 上想要 500 Mbps，必须窗口达到 4 MiB**（本次修正正好做到这一点），
且内核确实放行。内层 UDP 会打散到所有子流，不受这个单流上限约束。

### 上线前请确认（sysctl）

若启动日志出现窗口告警，或 `ss -ti` 看不到预期窗口，请执行：

```sh
sysctl -w net.core.rmem_max=16777216
sysctl -w net.core.wmem_max=16777216
sysctl -w net.ipv4.tcp_rmem='4096 1048576 16777216'
sysctl -w net.ipv4.tcp_wmem='4096 65536 16777216'
sysctl -w net.ipv4.tcp_congestion_control=bbr
sysctl -w net.core.default_qdisc=fq
```

并用 `ss -ti` 确认 `bbr` 生效、**qdisc 为 `fq`**（BBR 配 `fq` 以外的队列表现很差）。
以 root 运行则无需上述 sysctl，`SO_RCVBUFFORCE` 会直接绕过限制。

### 验证清单

1. 启动日志无 "TCP receive window is only ..." 告警
2. `ss -ti` 显示 `bbr`，且 `rcv_rtt`/`rcv_space` 达到 MB 级
3. `iperf3 -c <隧道对端> -P 8` 多条流聚合 ≥ 500 Mbps
4. `iperf3 -c <隧道对端>` 单条流视 RTT 达到上表预期值
5. 对比 `--subflows 1 / 4 / 8 / 16` 的聚合吞吐，确认递增

## UDP-in-TCP 在 4 subflows 下只有 ~60 Mbps 的原因与修正

### 诊断：乱序被误判为丢包

上一版把 UDP 打散改成**逐包轮转**（`spin` 每包 +1）。方向是对的，但粒度太细：

一条 UDP 流的包被轮流送到 N 条子流上，而各子流的队列深度、RTT、丢包情况都不同，
于是接收端**持续乱序**。QUIC 的乱序阈值是 3 个包，iperf3 UDP  likewise —— 持续乱序
会被解读为**持续丢包**，触发虚假丢包检测，拥塞窗口反复坍缩，流量根本爬不起来。

这就解释了"为什么 subflows 更多反而更慢"以及"为什么 UDP-in-TCP 比 TCP-in-TCP 还慢"：
TCP-in-TCP 被钉死在单条子流上，**完全有序**；UDP 那边却是每包乱序。

### 修正一：轮转粒度从"每包"改为"每 16 个包"（`UDP_ROTATE_EVERY = 16`）

`spin = counter.fetch_add(1) / UDP_ROTATE_EVERY`

形成**有序运行段（in-order runs）**：连续 16 个包走同一条子流（段内严格有序，乱序
计数器和 QUIC 丢包检测保持安静），段与段之间再换下一条。

- 16 个 1400 字节的包在 100 Mbps 下约 1.8 ms —— 一个 RTT 内会轮转几十次
- 所有子流**始终同时在飞**，窗口照样叠加，并行收益不丢
- 乱序只发生在段边界，且恰好落在"本来就要等"的场景

这是"打散"与"有序"之间的调节旋钮：设为 `1` 回到逐包轮转（仅接收端真的不怕乱序时
有用），调大则更接近钉死。

### 修正二：TCP 载波的默认 MTU 从 1400 提到 1500（`DEFAULT_TUN_MTU_TCP`）

UDP 载波保留 1400，因为外层 UDP 数据报要留出 IP/UDP 头与加密开销的余量，避免路径上
被分片。

TCP 载波**没有这个约束**——TCP 字节流由内核按自己的 MSS 分段，多 100 字节不会造成
外层分片。而 1400 的隧道 MTU 会让 UDP 应用惯用的 **1460 字节**数据报（1500 - 20 IP -
8 UDP）在隧道内被 **IP 分片**，分片会显著降低吞吐并放大丢包影响。

所以 TCP 载波默认 MTU = 1500，让 1460 字节的应用数据报完整通过。显式 `--mtu` 始终
优先，两种载波都适用。

### 预期效果

| 场景 | 修正前（4 subflows） | 修正后 |
| --- | --- | --- |
| UDP in TCP | ~60 Mbps | 100 Mbps+ |
| TCP in TCP | ~100 Mbps | 不变（仍钉死有序） |

内层 UDP 现在会打散到所有子流（并行收益），同时保持段内有序（不触发虚假丢包检测）。

### 调优建议

- 若某应用对乱序极敏感：调大 `UDP_ROTATE_EVERY`（32 / 64）
- 若接收端确实不怕乱序（如自研协议）：设为 `1` 取最大打散
- `--subflows` 建议 4 起步，配合 `--mtu 1500`（TCP 载波已默认）测试
- 测 UDP 吞吐用 `iperf3 -c <对端> -u -b 200M`，注意 iperf3 自身会报告丢包/乱序统计，
  这正是判断 `UDP_ROTATE_EVERY` 是否合适的最佳指标

## 吞吐：从 ~100 Mbps 到多核并行（目标 500 Mbps）

### 两个瓶颈叠加

实测 TCP-in-TCP 与 UDP-in-TCP 都卡在约 100 Mbps。原因有两个，且是叠加的：

**瓶颈一：发送窗口被锁死（约 100 Mbps 的天花板）**

`apply_tcp_buffers()` 的发送侧犯的正是接收侧文档里警告过的错误：
`SO_SNDBUF` 会被 clamp 到 `net.core.wmem_max`（默认 208 KiB），**并且**设置它会置
`SOCK_SNDBUF_LOCK`，禁用内核的发送缓冲自动调优。于是发送窗口锁在约 208 KiB：

```
208 KiB × 8 / 0.066 s ≈ 25 Mbit/s（单子流）
× 4 子流 ≈ 100 Mbit/s
```

与实测吻合——所以加子流完全没用，每条子流的窗口都被锁死。

**修正**：`SO_SNDBUFFORCE` 失败时**不再回退 `SO_SNDBUF`**，什么都不设，让自动调优
接管（上限 `net.ipv4.tcp_wmem[2]`，默认 4 MiB）。并新增发送侧窗口告警日志。

**瓶颈二：单任务串行做 AEAD（约 100 Mbps 的另一半）**

服务端/客户端两个方向原本都是**单 reader + 单 processor**：所有子流的包汇聚到一个
mpsc 后，由一个任务串行 de-obfs → 解密 → 路由 → 写 TUN（或反向加密 → 发送）。AEAD
是每包 CPU 密集操作，单核吞吐远低于千兆；再加上 TUN 每包一次 syscall。

**修正**：拆成 **reader + N 个 worker**（`worker_count()`，取
`available_parallelism()` clamp 到 2..=8，默认 4）。分发键按方向选择：

| 方向 | 分发键 | 理由 |
| --- | --- | --- |
| 服务端 carrier→TUN | peer 哈希（`recv_sharded` 的 shard）| 多子流/多客户端天然分散 |
| 服务端 TUN→carrier | 内层 5 元组哈希（`classify`）| TUN 读出的是明文，可按内层流分散 |
| 客户端 TUN→net | 内层 5 元组哈希 | 同上 |
| 客户端 net→TUN | 子流索引 | 包都来自同一 server 地址，按子流分 |

**同一条内层连接恒定落同一 worker**，顺序得以保持；不同连接并行跑在不同核上。
控制消息（keepalive/assign/route push）解密后由各 worker 处理，共享状态
（routing / NAT / installer）全部通过 `Mutex` / `RwLock` 访问。

任务生命周期用 `JoinSet`：`join_next()` 等第一个结束（reader 或任一 worker），
然后 `abort_all()` 收尾——任一端失败即整体退出，语义与原 `select!` 一致。

### 新增 API

* `shadowvpn::worker_count()` — worker 数量
* `Transport::recv_sharded()` — 额外返回分片索引 `(n, peer, shard)`
* `TcpHub::recv_shard` / `TcpClient::recv_shard` — 分别按 peer 哈希、子流索引分片
* 客户端 `TcpClient` 的 inbound 通道携带子流索引 `(usize, Vec<u8>)`

### 上线前请确认

以 root 运行（否则 `SO_SNDBUFFORCE` / `SO_RCVBUFFORCE` 拿不到 `CAP_NET_ADMIN`，
退回自动调优，窗口上限约 4 MiB 而非 16 MiB）：

```sh
sysctl -w net.core.rmem_max=16777216
sysctl -w net.core.wmem_max=16777216
sysctl -w net.ipv4.tcp_rmem='4096 1048576 16777216'
sysctl -w net.ipv4.tcp_wmem='4096 1048576 16777216'
sysctl -w net.ipv4.tcp_congestion_control=bbr
sysctl -w net.core.default_qdisc=fq
```

`iperf3 -P 8` 测聚合（单流只能吃到一条子流）。启动日志若有窗口告警，按提示调 sysctl。

## 2 核 ARM 实测解读：一个核 100%，另一个 43%

### 这组数字说明什么

总用量约 1.43 核，而不是接近 2.0。说明**第二个核没吃饱**——不是"CPU 不够"，是
**并行度不足 + 负载不均**。

结合调度设计，最可能的原因是单条内层流被钉死：

* 上行（TUN→carrier）按内层 5 元组哈希分片，一条流恒定落一个 worker；
* 下行（carrier→TUN）按子流索引分片，而**有序流量（内层 TCP）被钉死单子流**，
  所以一条流的所有回包也只从一个子流回来 → 也是一个 worker。

结果：两个方向各只有少量 worker 真正忙，其余空转。iperf3 单流（`-P 1`）时最明显——
**再多 worker 也只用到一个**。请确认测试用的是 `-P 8`；若已经是多流而第二核仍只有
43%，再看下面的 cipher 因素。

### 新增：`--workers N`（便于实测定位）

```bash
shadowvpn-client -c client.json -t tcp --workers 4
```

```json
{ "transport": "tcp", "workers": 4 }
```

显式值原样生效（下限 1），不做二次猜测——这个参数就是用来量瓶颈在哪的。默认仍由
CPU 核数推导（`available_parallelism()` clamp 到 2..=8）。

**怎么用**：在 2 核上依次试 1 / 2 / 4 / 8。

* 吞吐基本不变 → 瓶颈不在 worker 数，而在串行读路径或 cipher；
* 吞吐明显上升 → 之前是并行度不足；
* 吞吐**下降** → 任务超订阅，切换开销反噬。

### 先做这个实验：`cipher: none` 对照

这是区分"CPU 花在加解密"还是"花在 I/O 与调度"的最快办法：

```bash
# 两端同时改为 none，同样跑 iperf3 -P 8
shadowvpn-server -l 0.0.0.0:8388 -t tcp -m none --tun-ip 10.9.0.1 --peer-ip 10.9.0.2
shadowvpn-client -s host:8388 -t tcp -m none --workers 2
```

* `none` 下能到 500 Mbps → 瓶颈是 AEAD，换 cipher 或接受更低目标；
* `none` 下仍只有约 100 Mbps → 瓶颈是 syscall / 串行读，加 worker 无用。

### ARM 上的 cipher 选择

`aarch64` 构建已开 `+aes,+neon`。但两者快慢取决于具体核心：

| 核心 | 建议 |
| --- | --- |
| Cortex-A53 / A55（多数廉价盒子、部分路由器）| `chacha20-poly1305` |
| Cortex-A72 / A76 及更高、Apple Silicon、Graviton | `aes-256-gcm`（PMULL 加速 GHASH）|

**实测两遍，别猜。** 同样的思路，在目标设备上编译比交叉编译更快：

```bash
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

（`.cargo/config.toml` 里已有注释备好的一行；注意 `target-cpu=native` 的产物不跨机
可移植。）

### 关于 500 Mbps 这个目标，需要说实话

2 核 ARM 是很紧的约束。粗算（假设 1.5 GHz）：

```
500 Mbit/s ÷ (1400 B × 8) ≈ 44,600 pps（单向），双向约 89,000 pps
两核合计预算 ≈ 3e9 / 89e3 ≈ 33,000 cycles/包
```

而每包实际要花：AEAD 双向约 3,000–6,000 cycles、四次 syscall 约 12,000 cycles、
拷贝/哈希/调度约 5,000 cycles——合计约 20,000–23,000 cycles。

**理论上够，但余量很小**，任何一项超预期（更慢的核、更大的 pps、丢包重传）都会掉
下来。所以：

* `cipher: none` 或最轻 cipher 下，500 Mbps 有希望；
* 完整 AEAD 下，2 核 ARM 上更现实的预期是 200–350 Mbps；
* 若必须 500 Mbps 且要加密，换 4 核以上的机器比继续调代码更直接。

## "再加线程能不能提速" —— 不能，瓶颈不在这里

### 先澄清：线程早就开了

`#[tokio::main]` **默认就是多线程 runtime**（`flavor = "multi_thread"`，worker
threads = CPU 核数）。加上上一轮的 N 个 worker（`worker_count()`，2..=8），
AEAD / de-obfs 已经在多核上并行了。所以"再增加程序线程"不会带来可观收益——
线程已经够，问题在别处。

### 真正的天花板：单 fd 串行 I/O

阿姆达尔定律。无论后面有多少 worker，两个方向的**读**都各是一个任务：

* 服务端：`tun_to_udp` 的 reader 读 TUN；`udp_to_tun` 的 reader 读 carrier
* 客户端：`tun_to_net` 的 reader 读 TUN；`net_to_tun` 的 reader 读 carrier

TUN 和 carrier socket 各自只有**一个 fd，只能顺序读**。每包固定成本：

1. 一次 `read` syscall
2. 一次 `to_vec()` **堆分配** + memcpy
3. `classify()` 哈希
4. 一次 channel send

这条路径**无法并行**——它的吞吐上限就是整条链路的上限，后面的 worker 再多也喂不饱。
此外还有两个共享点：服务端每包一把全局 `std::sync::Mutex<Routing>`；所有 worker
写同一个 TUN fd，内核侧串行化。

### 量化

500 Mbit/s ÷ (1400 B × 8) ≈ **44,600 pps**，双向约 90,000 pps
⇒ 单 reader 每包预算约 **11 µs**。而一次 syscall + 一次堆分配就已接近这个量级。
所以这是硬天花板，不是参数没调好。

### 本轮实际做的改进：入口学习节流

服务端学习模式（默认）下，**每个入站包**都要在全局路由锁内走完整套：

```
resolve owner (node_for_ip4/ip6) → node_for_peer → learn() → get_mut → peers.contains()
```

其中 `peers.contains()` 是 O(n) 线性扫描，且整段是**写**操作——在 45k pps 下既吃一个核
的份额，又让多个 worker 反复争抢同一条 cache line。

但映射在流建立后就**不再变化**（子流在连接时确定）。所以改为定时重校验：

* 新增 `ClientEntry::learn_checked` 与 `Learned::touch()`
* 数据面热路径先调 `touch(src, now)`：命中且距上次完整校验 < `LEARN_REFRESH`
  (200 ms) 时，**只刷新 `last_seen`** 并跳过 owner 校验与 peer 扫描
* `maybe_learn()` 本身语义未变，控制消息路径与既有测试不受影响
* 最坏情况：一个真正的新 endpoint 被延迟最多 200 ms 采纳

### 若还要继续往上，方向是"减少每包固定开销"，不是"加线程"

1. **消除 `to_vec()`** —— 缓冲池化 / `bytes::Bytes`，去掉每包堆分配
2. **批量 I/O** —— TUN 侧 `readv`/`writev` 一次搬运多包，摊薄 syscall
3. **多队列 TUN** —— Linux `IFF_MULTI_QUEUE`，每个 fd 一条队列，读写才真能并行
   （需确认 tun-rs 2.8 是否暴露该能力）

前两项需要改通道传递的类型，第三项依赖库支持——都属于较大重构，建议先确认当前
实测离目标差多少再决定是否投入。

## TCP 随机长度填充（Padding）

### 需求

抓包发现客户端与服务端在握手阶段出现**固定长度**的 TCP 包，希望 TCP 模式加入随机
长度填充。

### 为什么固定长度是个问题

加密只掩盖**内容**，掩盖不了**长度**。而握手阶段尤其危险：keepalive、分配请求、DNS
查询各有其标志性的固定大小，于是被动观察者每次会话都在同样的位置看到同样几个长度值
——即使内容加密，这本身就是一个指纹。填充把每个长度打散到一个区间内，消除这个侧信道。

注意这是**混淆**而非**安全**手段：它不增加任何密码学强度，只是去掉长度侧信道。

### 帧格式

```text
padding 关闭： [ u16 payload_len ][ payload ]
padding 开启： [ u16 payload_len ][ u8 pad_len ][ payload ][ pad bytes ]
```

`payload_len` **只计载荷**，不含填充——这样 plausibility 检查（判断对端是否说了我们的
协议）仍然基于真实载荷长度，不受填充干扰。

**两种模式不互通**：开启填充会改变帧布局，两端必须一致（但上限可以不同，因为 pad_len
是每帧单独读的）。这和 `transport`、`cipher` 必须两端一致是同一类约束。

### 实现要点

1. **长度与内容都随机**
   填充长度每帧随机取 `0..=pad_max`；填充内容也随机生成。固定长度等于没做，固定内容
   则会被注意到的人直接剥离。

2. **上限受 u8 字段约束**
   `pad_len` 字段是单个 `u8`，所以最大 255。配置值超过就报 `ConfigError::Invalid`
   （而不是静默截断——静默截断会掩盖配置错误）。

3. **缓冲区按填充后的尺寸计算**
   新增 `max_tcp_wire_size(cipher, pad_max)`；读写缓冲必须按**线上帧**大小分配，否则
   一个填满的帧会被判为超长而丢弃。

4. **`TcpOptions` 聚合参数**
   `buf_len` / `validator` / `plausible` / `padding` 打包成一个结构，避免逐个传参
   （参数已经多到容易漏）。

5. **非 TCP 强制为 0**
   UDP 没有帧布局可填充，配置里写了也忽略。

### 配置

```json
{ "transport": "tcp", "padding": 64 }
```

```bash
shadowvpn-server -l 0.0.0.0:8388 -t tcp --padding 64 ...
shadowvpn-client -s host:8388 -t tcp --padding 64 ...
```

默认 `DEFAULT_PADDING_MAX = 64`；`0` 关闭。

### 开销

1400 字节的帧配 64 字节上限，带宽开销约 4%（填充长度均匀分布在 0..=64，均值 32）。
每帧多一次 `rand::rng()` 调用，可忽略。

### 测试

* 帧格式往返（开/关两种）
* 多帧连续解析时填充被完整跳过、不污染下一帧
* 填充长度确实在变化（而非固定）
* 填充长度不越界
* 空载荷 / 超长载荷被拒
* 传输截断时不产出伪造帧
* 配置：TCP 默认值、UDP 强制 0、显式值生效、越界报错

## 服务端 TCP 反探测：FORCE RESET

### 需求

服务端传输模式为 TCP 时，收到不属于本协议（端口扫描、HTTP/TLS 握手探测、错误 PSK）
的 TCP 包，应强制 RESET 而不是丢包了事。

### 为什么不能只丢包

丢包后连接仍然保持打开：扫描器能确认"这里有服务在监听"，并可继续向这个 socket
推送数据。RESET 则立刻关上门——连握手都完成不了。

### 实现

1. **`net::force_reset_fd()`**（unix）
   按序做两件事：
   - `SO_LINGER{l_onoff=1, l_linger=0}`：让随后的 `close()` 发 **RST** 而非 FIN。
     否则连接会停在 FIN_WAIT，对端看到的是"有序关闭"，仍可读出服务存在。
   - `shutdown(SHUT_RDWR)`：立刻结束连接。这会唤醒阻塞中的 `read` 使其返回 EOF，
     读循环随即退出并释放 socket——释放 socket 正是发出 RST 的那一步。

2. **`transport::ConnAbort`**
   accept 时为每个连接建立句柄：
   - `notify: Arc<Notify>` —— 唤醒读/写两个循环
   - `fd: Option<OwnedFd>` —— socket 的 `dup`。`setsockopt` 与 `shutdown` 作用于
     socket 本身而非描述符，所以 dup 出来的 fd 一样有效。

3. **读/写循环支持中止**
   读循环改为 `select! { next_frame, abort.notified() }`；写循环同样 select，
   且从 `outbound` map 中移除 sender 会让 `recv()` 返回 None。两条路都覆盖。
   中止信号用 `notify_waiters()`（唤醒当前等待者）+ `notify_one()`（留存一个
   permit 给正好在迭代中的循环），确保不丢。

4. **`Transport::force_reset(peer)`**
   先移除 outbound（停止向其发包），再 `fire()`。UDP 与客户端侧为 no-op。

5. **服务端触发点**（`bin/server.rs`）
   - obfs 解包失败 → 非本协议的封装
   - AEAD 认证失败 → 发送方不持有共享密钥

### 为什么不会误伤正常客户端

AEAD 认证失败在构造上就意味着"对方不持有共享密钥"。配置正确的客户端几乎不可能触发
（只会是链路位翻转，极罕见），因此立即 RESET 是安全的。

## 修正：服务端 TCP 收到非法包后仍未 RESET（真正的根因）

上一版把 force reset 挂在**数据面 processor** 上（obfs 解包失败 / AEAD 认证失败 →
reset）。逻辑没错，但**那两条路径永远走不到**，所以实测"仍然默默等到超时"。

### 为什么走不到

TCP 载波用 **2 字节大端长度前缀**定界。`FrameReader::next_frame()` 的内部逻辑是：
读前缀 → 得到 `len` → 一直 `read` 直到攒够 `len` 字节 → 才返回一帧给上层。

而探测包的首 2 字节会被**当成长度前缀误读**：

| 探测 | 首 2 字节 | 被解析成的 len | 实际发送字节 |
| --- | --- | --- | --- |
| `curl http://host:port/` | `"GE"` | **18245** | ~78 |
| TLS ClientHello | `0x16 0x03` | **5635** | ~300 |

于是 `next_frame()` 永远等不到那 18245 / 5635 字节，**卡在内部的 `read().await` 上**。
processor 收不到任何帧 → 自然不会触发 force_reset → 只能等 OS 超时。

这正是"服务端只是默默等待"的全部原因。

### 修正

1. **`FrameReader` 支持读超时**
   新增 `ReadDeadline` 策略，区分两种"等待"：
   - `Unverified`（首帧尚未通过校验）：**每次 read 都有上限**。静默连接 10s
     （`FIRST_FRAME_TIMEOUT`），已收到部分字节则收紧到 3s（`STALLED_FRAME_TIMEOUT`）。
   - `Verified`（已认证）：空闲是正常的（客户端在 keepalive 之间本来就不发东西），
     所以**只对"半截帧"设 3s 上限**，空闲不设限——否则会误杀正常客户端。
   超时返回 `NextFrame::Stalled`，不再无限阻塞。

2. **首帧内容校验（`Validator`）**
   光有超时还不够：若探测恰好凑够了自己谎报的长度（例如发 `len=4` 再发 4 字节垃圾），
   会组成一帧并交给 processor。所以在读循环里对**第一个帧**直接做校验：
   de-obfs → decrypt → 通过才算合法。失败立即 reset。
   只校验首帧——扫描器无法造出能认证通过的首帧，抓得住所有探测，又不给数据面每包
   加 AEAD 开销。
   `cipher=none` 时没有 AEAD 可依，改为形态校验：是 IP 包（`len>=20 && ip_src` 可解析）
   **或**是控制消息（`mesh::is_control`，keepalive/assign 不是 IP 包，却是客户端连上来
   发的第一件事——这一条漏了会把合法客户端首帧误杀）。

3. **两条路径都触发 reset**：`Stalled` 与首帧校验失败，都调 `abort.fire()`。

### 效果

| 探测方式 | 上一版 | 修正后 |
| --- | --- | --- |
| `curl`（"GE" → 18245 字节） | 挂起到 OS 超时 | **~3s 内 RST** |
| TLS ClientHello（5635 字节） | 挂起到 OS 超时 | **~3s 内 RST** |
| 连上什么都不发 | 挂起到 OS 超时 | **10s 内 RST** |
| 凑够长度的垃圾帧 | processor 兜底 reset | 首帧校验即 reset |

### 验证方法

```sh
# 服务端 TCP 模式运行后
time curl -v http://<server>:8388/      # 应在 3s 内 Connection reset by peer
openssl s_client -connect <server>:8388 # 同上
nc -v <server>:8388 < /dev/null         # 静默连接，10s 内 reset
```

服务端日志会出现 `tcp: peer did not produce a complete frame in time (partial
frame stalled), resetting` 或 `tcp: first frame failed validation, resetting`。

## 修正（第二轮）：发的是 FIN 不是 RST

上一轮修好了"探测包首 2 字节被当长度前缀 → 卡在 read 上"的问题，超时与校验都能触发
reset 了。但实测**发出的是正常关闭（FIN），不是强制重置（RST）**。

### 根因：`shutdown()` 本身就是"优雅关闭"

上一版的 `force_reset_fd()` 做了两步：

```rust
setsockopt(SO_LINGER, {l_onoff: 1, l_linger: 0});  // 让 close() 发 RST
shutdown(fd, SHUT_RDWR);                            // ← 问题在这里
```

`shutdown()` 是**有序**关闭：它立刻发出 **FIN**，连接进入 FIN_WAIT。到这一步，连接
已经在优雅关闭了，之后的 `close()`——无论有没有 SO_LINGER——都没有东西可以中止，
于是对端观察到的是一次**正常关闭**。

这正是"只是实现了 TCP 关闭连接"的全部原因。**SO_LINGER 和 shutdown 是互斥的两种
语义，不能一起用。**

### 修正

1. **删掉 `shutdown()`**，函数改名 `arm_tcp_reset()`，只负责设 `SO_LINGER`。
   RST 在 socket 最后一个 fd 被关闭时由内核发出——这才是正确的时序。

2. **`ConnAbort::fire()` 关闭我们持有的 dup fd**
   一个 socket 有多个 fd：`into_split()` 的两个半共享一个，加上我们 `dup()` 的那个。
   只有**最后一个** fd 关闭才真正 close socket → 才发 RST。
   所以 `fire()` 现在：设 SO_LINGER → `take()` 并 drop dup fd → notify 让两个循环
   drop 各自的半 → 引用归零 → close → **RST**。
   `fd` 改为 `Mutex<Option<OwnedFd>>` 以便 `take()`；加 `fired: AtomicBool` 防重复。

3. **超长帧即时判定（`plausible_frame_limit`）**
   除了等超时，现在还做**瞬时**判定：长度前缀声明超过合理上界即非法，立即 reset。
   上界由 MTU 推导（`mtu + 512`），不是硬编码——MTU 大的隧道本来就会产生大帧，
   写死一个值会误杀。客户端传 `MAX_TCP_FRAME`（等于不限制，它信任自己拨的服务端）。

| 探测 | 首 2 字节 | 被解析的 len | MTU 1500 时上界 2012 | 结果 |
| --- | --- | --- | --- | --- |
| `curl` | `"GE"` | 18245 | 超出 | **立即 RST** |
| TLS ClientHello | `0x16 0x03` | 5635 | 超出 | **立即 RST** |
| SSH banner | `"SS"` | 21331 | 超出 | **立即 RST** |
| 连上后不发数据 | — | — | — | 10s 内 RST |
| 发了数据但凑不满一帧 | — | 合法长度 | 未超 | 3s 内 RST |

### 覆盖的握手失败路径

连接被 accept 后，以下任一情况都会 **RST**（不是 FIN）：

1. 长度前缀声明超过合理上界 → 立即
2. 首帧未通过校验（de-obfs → decrypt 失败；`cipher=none` 时形态检查失败）→ 立即
3. 收到部分字节但帧迟迟不完整 → 3s（`STALLED_FRAME_TIMEOUT`）
4. 连接后完全不发数据 → 10s（`FIRST_FRAME_TIMEOUT`）
5. 已认证连接后续帧解包/认证失败（processor 路径）→ 立即

### 如何确认发出的是 RST 而非 FIN

```sh
# 客户端侧抓包
sudo tcpdump -i any -nn 'host <server-ip> and port 8388'
# 另开终端
curl -v http://<server-ip>:8388/
```

应看到服务端回 `Flags [R.]` 或 `[R]`（RST），**而不是** `[F.]`（FIN）。
`curl` 侧报错应为 `Connection reset by peer`，而非 `Connection closed`。

## 修正（第三轮）：服务端仍会发出 FIN+ACK

抓包确认 RST 已经发出，但**同一次连接里还夹着一个 FIN+ACK**。期望是：握手失败的连接
只发 RST，绝不发 FIN。

### 根因：`into_split()` 的写半在 drop 时走优雅关闭

上一版已经把 `shutdown()` 从 `arm_tcp_reset()` 里删掉了，我们自己的代码不再发 FIN。
但 FIN 还有另一个来源，来自 tokio 而不是我们：

```rust
let (reader, writer) = stream.into_split();   // OwnedReadHalf / OwnedWriteHalf
```

`OwnedWriteHalf` 的销毁路径**不受我们控制**——它会走一次有序 `shutdown()`，也就是
发 FIN。于是时序变成：

1. 写半被 drop → `shutdown()` → **服务端发出 FIN+ACK**
2. 之后所有 fd 归零 → `close()`，此时 SO_LINGER 已设 → **服务端发出 RST**

抓包里 RST 与 FIN+ACK 同时出现，正是这两步叠加的结果。

### 修正：不再 `into_split()`，改用 `Arc<TcpStream>` 共享同一个 socket

新增 `SharedRead` / `SharedWrite`：各持一个 `Arc<TcpStream>`，用 `try_read` /
`try_write` 配合 `poll_read_ready` / `poll_write_ready` 实现 `AsyncRead` /
`AsyncWrite`。读写两个任务共享同一个 socket，但**没有任何人持有"写半"这种会在
销毁时 shutdown 的对象**。

于是销毁路径只剩一种：

* 最后一个 `Arc<TcpStream>` 被 drop → tokio 直接 `close(fd)`（tokio 的 `TcpStream`
  销毁只关 fd，不调 shutdown）
* 若此时 SO_LINGER 已设（force-reset 场景）→ 内核发 **RST**，且**不会有 FIN**
* 若未设（正常客户端断开）→ 一次普通的 FIN 关闭，合法连接行为不变

另外把 `AsyncWrite::poll_shutdown` 显式写成**空操作**并注明原因：半关闭只会重新引入
FIN，隧道也从不要求半关闭。

### 为什么这比"想办法阻止写半 drop"更可靠

阻止 drop 需要依赖 tokio 内部实现细节（写半到底会不会 shutdown、有没有 `forget()`
之类的逃生口），版本一变就失效。而"根本不产生写半"是结构上的保证，与 tokio 内部
行为无关。

### 复验

```sh
sudo tcpdump -i any -nn 'host <server-ip> and port 8388'
curl -v http://<server-ip>:8388/
```

该连接上服务端应**只有** `[R]` / `[R.]`，**不应出现** `[F.]` / `[F]`。
若仍有 FIN，请确认抓的是被 reset 的那条连接（curl 可能因重试而新建连接）。

## 编译时开启硬件 AES

引用说明："To use AES-GCM at full speed on ARM, build with the crypto features
enabled, e.g. `RUSTFLAGS="-C target-feature=+aes,+neon"`"。

**x86_64 不需要**：`aes` crate 在 x86 上是**运行时**检测 AES-NI，可移植构建在支持的
CPU 上仍会用到它（本机编译可用 `-C target-cpu=native`）。

**aarch64 必须开启**：没有运行时分发，ARMv8 crypto 指令只有在编译时开启 `+aes`
才会被生成；否则退回软件查表实现，慢数倍。在路由器级 ARM 核上，这是能否跑满链路的
差别。

已做的两处配置：

1. **`.cargo/config.toml`**
   ```toml
   [target.aarch64-unknown-linux-musl]
   rustflags = ["-C", "target-feature=+aes,+neon"]
   ```
   本地 / cross 构建自动生效。

2. **`.github/workflows/release.yml`**
   矩阵每个目标带 `rustflags` 字段；注意 **RUSTFLAGS 环境变量会覆盖 config.toml
   的 rustflags**，所以 CI 里必须重复写：
   ```yaml
   RUSTFLAGS: -C strip=symbols ${{ matrix.rustflags }}
   ```

### 重要前提：确认硬件支持

AES 是 ARMv8-A 的**可选**扩展。开启 `+aes` 后，在没有该扩展的核上会 **SIGILL**。

```sh
grep -m1 -o 'aes' /proc/cpuinfo
```

自 Cortex-A53/A57 起的主流核（Pi 3/4、多数路由器、Apple Silicon、Graviton）都具备。
若有目标设备不支持，去掉 `+aes`、保留 `+neon`，或单独出一个可移植构建。

**armv7 保持默认**：32 位 ARM 的 crypto 支持非常不统一，风险高于收益。若确认所有
目标设备都支持，可自行加 `-C target-feature=+aes,+neon`。

## 验证状态

本次交付在未安装 Rust 工具链、且无法联网拉取 crates 的环境中完成，**未做真实 `cargo build` 编译验证**；已通过括号配平自检与逐处静态审查。请先在 x64 宿主执行 `cargo build --release` 与 `cargo test` 跑通，再做交叉编译。
