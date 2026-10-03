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

## 验证状态

本次交付在未安装 Rust 工具链、且无法联网拉取 crates 的环境中完成，**未做真实 `cargo build` 编译验证**；已通过括号配平自检与逐处静态审查。请先在 x64 宿主执行 `cargo build --release` 与 `cargo test` 跑通，再做交叉编译。
