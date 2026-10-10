# mem_crypt — 进程内存块加解密（r133）

双帧分视（dual-frame split view）的进程内存块加密：目标进程自己读写的
永远是**明文**，其他一切观察者（`readvm`、物理扫描、其他进程/内核线程）
看到的是**密文**。切入/切出零开销——不做 Cr3Encrypt 式的切出回写，数据
永远不动，动的只有 NPT 视图映射。

## 语义

```
                ┌─ 目标进程（CR3 = target）──→ ProcView: GPA ─→ 私有明文帧
用户 VA ─→ 用户页表 ─┤
                └─ 其他一切 CR3 ──────────→ base view: GPA ─→ 原帧（密文）
```

- `crypt enc <pid> <va> <size> <key>`（ctl 侧自动跑完整两阶段）：
  - **stage-1（action 0，ARMED）**：挂起目标 → `Cr3M4ArmProcessView` 幂等武装
    → 逐页 `OverlaySlotMap`（明文整页拷进私有帧 + MDL pin + 视图换帧 +
    `TlbKickFlushAllCores`）→ 拍每 vCPU ExitCount 快照 → **保持冻结返回**。
    原帧此时仍是明文（任何未刷新翻译读到的都正确）。
  - **gate（ctl）**：逐核 pinned intercepted-CPUID nudge（r130 reap 律），
    直到驱动确认每核都已越过快照（kick 已消费 = 缓存翻译已冲刷）。
  - **seal（action 3）**：密文写入原帧（`MmMapIoSpace` 物理别名，确定性
    落帧）→ **补上 stage-1 欠的那次 resume**。写入期间目标冻结，写者集合
    = {驱动}。
- `crypt dec <pid> <va>`：私有帧就是明文权威（加密期间目标的所有写都落
  在它上面）——拷回原帧 → `OverlaySlotUnmap`（identity 恢复 + r130 墓园
  park）。**Key 不参与解密**；从任何部分 enc/seal 状态都能完成，并补齐
  冻结账目。
- 卸载：`MemCryptDeinit`（`OfflineTeardown` 首行，先于 `gHooks->Deinit`）
  ——**顺序铁律：先回写明文、再 freeNow 释放 overlay**。反序 = 明文帧先被
  释放、原帧永远留密文 = 数据损坏。同样补冻结账目。

## 视图同步契约（r133 实测定律）

per-core NCr3 只在 **VM exit 时**由策略重发布（r120 模型；CR3-write 拦截
是 r42/r48 实证的 guest 杀手，不可用）。因此：

- **无 exit 的访问纪元若迁移到仍持有陈旧 base NCr3 的核，会读到原帧 =
  密文**。
- 部署契约：受保护目标在块访问点取一次 intercepted CPUID（同步点）——
  该 exit 落在当前核、目标 CR3 current，ProcView 在后续访问前生效。
  `tests/mcrypt_target.c` 的每个自检纪元开头即此同步点（e2e 实测
  ok=4 damaged=0）。
- 任意无 exit 目标需要结构性修复（npt.h M4 prerequisite 记载的 per-core
  view selection），r133 范围外。
- **U/S=0 base 视图陷阱路线已试并否决**（r133 第 3 轮）：r32 无条件故障
  律对内核自己的触碰者（工作集/内存压缩的 direct-map 走行）同样生效，
  seal 后一秒内即被 FOREIGN fault 解除（内核日志实证），陷阱不可维持。
  npf.cpp 的 deny 链第二槽（`NpfSetDenyCallback2`）作为通用缝保留。

## 已验证（r133 e2e，2026-10-10）

- 全周期：baseline readvm=明文 → enc sealed → **readvm=密文（操作员侧）
  且目标自检 4/4 明文（目标侧）** → dec → readvm 复原 → list 0 live。
- hold + 卸载回写：块保持 sealed 下 `sc stop`（DevUnload 回写明文）→
  `sc start` → 子进程穿越全程**零坏字节**（findstr 无 DAMAGED 行，末尾
  自检 plaintext-ok）。
- 离线自测 347 检查 0 失败（含 TestCryptStream 9 项：identity/偏移连续/
  跨页形状/异 key 分歧/零参 no-op）。

## 密钥流（XOR keystream）

`CryptXorStream(key, blockOffset, buf, len)`（`modules/mem_crypt.cpp`，
纯函数，离线自测 `TestCryptStream`）：

- 字 = `Mix64(key ^ ((idx+1) * 0x9E3779B97F4A7C15))`，splitmix64
  finalizer；每 8 字节窗口一个字，小端字节序；
- **按块偏移寻址**：任意 offset O(1) 跳入，同一块内逐页调用 == 整块
  一次调用（跨页连续性是测试钉死的契约）；
- `key==0` / `len==0` 纯函数 no-op（IOCTL 层对 key==0 直接拒绝）；
- 强度档位：防内存扫描/取证读取足够；密文+已知明文的定向分析可破
  （keystream 可被推出）。接口统一 key+offset+buf+len，后续可换
  RC4/ChaCha20 无损升级。

## 协议

`SVMB_IOCTL_CR3_CRYPT = SVMB_CTL(0x82E)`，`SVMB_CR3_CRYPT`（tail-append
ABI 纪律）：Action 0=enc stage-1（ARMED+冻结）/ 1=dec / 2=list /
3=seal（BUSY=核未越代，ctl nudge 后重试）；OutStatus = 处理页数（或
list 的块总数）；Blocks[8] 披露。ctl 动词：`crypt enc|dec|list`（enc
自动跑 stage1→nudge→seal 全程）、`crypte2e [hold|chk]`（判定链）。

## 一致性 / 生命周期

- 挂起包裹所有原帧写：写者集合 = {驱动}，stale-TLB 竞态不存在；
- 进程退出：`MemCryptSweepPid` 只删块记录；overlay 本身由
  npt_hook_mgr 的 `UserProcNotify` 扫（帧随进程回收，密文同亡）；
  `Deinit` 对 LookupFrame 落空的页跳过——死目标帧永不被写；
- `OverlayLookupFrame`（npt_hook_mgr 新增公开查询）返回双帧对
  （原帧 PA + 私有帧内核 VA）；
- **硬崩溃恢复是手动的**：驱动死了 NPT 即关，目标读到密文。恢复 =
  `readvm` 拉密文 + 块 Key（`crypt list` / 日志）重建 keystream 异或
  + `writevm` 写回。这是 Key 留在块记录里的唯一原因。

## 约束

- 单目标进程（r120 单绑定槽；第二 LIVE 目标 DEVICE_BUSY，死目标的槽可
  被抢占复用——r133 审查轮加入）；
- **绑定槽保留语义**（审查 P2-3）：dec 后槽仍被旧 pid 持有直到该 pid
  退出或下次 arm——对同一 pid 的连续 enc/dec 无影响，换 pid 需旧 pid
  死亡；同时**不要**在 crypt 目标存活期间用 `cr3 watch`/raw-CR3 配置
  武装其他目标（配置路径不写 M4Pid，会把绑定从活着的 crypt 目标手上
  抢走，目标从此跑在 base 视图读密文——审查 P2-2）；
- 卸载为两阶段（审查 P0-1 修复）：先对全部块回写明文+解除冻结，再一次
  `OverlayUnmapForPid(0, true)` 清场（freeNow 分支无视 pid，逐块调用
  会把后续块的私有帧提前释放=明文丢失）；
- hv 已停止时 enc/seal 拒绝（审查 P2-1：无 NPT 重定向的世界里写密文=
  数据可见性损坏；dec 保持放行=恢复路径）；stage-1 的挂起不可用或
  失败时 enc 直接拒绝（审查 P1-2：冻结是承重的，不能记账了事）；
- 块页数受 overlay 槽约束（overlay+hook 全局共 32；
  `SVMB_CRYPT_MAX_PAGES`）；
- 仅私有用户数据页：共享帧（模块代码页等）加密会把密文写给所有
  映射者；代码页另继承 slide 的 EXEC 态权衡，MVP 不做；
- BaseVa 4K 对齐、Size 4K 倍数，IOCTL 层强校验。

## E2E（验收形状）

guest 跑 `mcrypt_target.exe`（打印 pid/VA/明文前 16 字节，2s 自检）→
`crypt enc` → `npt hook` action 11 (ovlstat) 对账 live=页数 → 双证：
目标自检持续 plaintext-ok 且宿主 `cr3 readvm` 同 VA ≠ 明文（密文）→
`crypt dec` → readvm 复原明文 → enc 状态下卸载驱动验证 unload 回写。

## 产线门适配（本仓 Debug 也定义 SVMB_PRODUCTION 时）

- HV 由 `AutoStart=1`（默认）在加载期进入，`ctl start` 被拒是预期；
- `readvm` 默认关：加载前注册表 `Parameters\ReadVmEnable=1`。
