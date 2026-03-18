# GDB Stub 安全与健壮性修复说明

## 背景

在代码审查中发现两处与 RSP 报文处理相关的风险：

1. 线程列表组包边界检查不严谨，存在潜在越界风险。
2. `X` 二进制写内存命令使用 `strlen()` 计算 payload 长度，遇到 `\0` 字节会截断。

这两处问题都位于 `gdb.c` 的通用协议处理路径。

---

## 问题 1：`qfThreadInfo` 组包边界风险

### 风险描述

`qfThreadInfo` 使用固定栈缓冲区拼接 vCPU 线程 ID。旧实现对 `snprintf`
返回值处理不完整，在大 vCPU 数场景有潜在越界风险。

### 修复策略

- 每次拼接前计算剩余空间 `rem`
- 采用单次 `snprintf` 写入 `",%x"` 或 `"%x"`
- 当返回值超出剩余空间时，立即截断到缓冲区末尾并退出循环

### 修复效果

- 消除越界写入风险
- 在超大线程数场景下安全截断输出

---

## 问题 2：`X` 二进制 payload 长度错误

### 风险描述

`X addr,len:data` 是二进制 payload，允许 `\0`。旧实现使用 `strlen(data)`，
会在 `\0` 处提前终止，导致反转义与写入长度错误。

### 修复策略

- 将 `handle_packet()` 改为接收原始报文长度 `pkt_len`
- 对 `X` 命令使用 `pkt_end - data` 计算真实 payload 字节数
- 不再依赖 C 字符串终止符

### 修复效果

- 二进制 payload（含 `\0`）可正确解析
- 避免写内存路径的协议截断错误

---

## 关联修改点

- `gdb.c`
  - `handle_packet()` 签名增加 `pkt_len`
  - `run_debug_session()` 与运行态包处理更新调用参数
  - `X` 命令长度处理改为真实报文边界
  - `qfThreadInfo` 组包改为严格边界控制

---

## 验证建议

1. 构建验证：`make`
2. 烟测验证：`make -C tests/gdb smoke`
3. 协议回归（建议）：
   - 使用包含 `\0` 与转义字符的 `X` payload 进行写入/读回校验
   - 在较大 vCPU 数下请求 `qfThreadInfo`，确认无异常

---

## arm64 提交安全审查结论

本次对 `arm/aarch64/gdb.c` 与其关联通用路径进行了安全审查，结论如下：

1. **未发现新增堆内存泄漏路径**
   - arm64 架构文件本身未引入 `malloc/calloc/realloc` 动态分配
   - 主要资源操作为 `KVM_GET/SET_ONE_REG`、`KVM_SET_GUEST_DEBUG` ioctls

2. **未发现新增典型内存破坏风险**
   - 寄存器读写使用固定大小 `memcpy`，并有寄存器号和长度边界判断
   - watchpoint BAS 计算对 `len` 与对齐偏移做了显式约束

3. **单步抗中断逻辑状态可回收**
   - DAIF 临时屏蔽状态通过 `step_irq_state.pending` 跟踪
   - 在 stop 回调中恢复并清理状态，未见悬挂分配或重复释放问题

### 建议持续关注

- 在 arm64 真实运行环境补充长期压力回归（高频中断 + 连续 `n/s/finish`）
- 若后续引入动态缓冲区或更多 RSP 扩展，沿用本文件的边界检查策略
