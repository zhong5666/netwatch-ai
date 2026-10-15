# netwatch-ai 🛰️

**网络巡检 + AI 告警** —— 定时巡检局域网设备，出问题用大模型分析原因，微信通知你。

## 为什么做这个

网络运维日常最烦的就是"设备挂了没人知道"。本项目把三件事串成闭环：

```
定时巡检(ping) → 检出异常 → AI分析原因 → 微信告警
```

AI 不是简单报"ping 不通"，而是结合上下文判断：是单台宕机？还是全网中断（核心设备挂）？并给出修复第一步。

## 架构

```
config.yaml ──► netwatch.py ──► analyzer.py ──► 微信
  设备清单      巡检+异常检测    deepseek 分析    (Hermes cron 投递)
```

## 快速开始

```bash
# 1. 装依赖
pip install -r requirements.txt

# 2. 改配置（设备清单在 config.yaml）
#    把 AI 的 API key 设成环境变量（不写进代码）
export NETWATCH_API_KEY=sk-xxx          # 或复用你已有的中转 key

# 3. 跑一轮巡检
python netwatch.py --once

# 4. 定时跑（每5分钟，正常静默、异常才报）
python netwatch.py --ai --silent-ok
```

## 功能特性

- ✅ ping 巡检，连续 N 次离线才报（抗抖动，不误报）
- ✅ AI 故障诊断（deepseek，判断宕机/断网/链路故障）
- ✅ 静默模式：全正常零打扰，出问题才说话
- ✅ 状态持久化（.state.yaml 记录离线连续次数）
- ✅ 无重依赖（标准库 + PyYAML，API 用 urllib 直接调）

## 技术要点（面试可讲）

- **子串陷阱**：Windows ping 输出 "100% 丢失" 含 "0%" 子串，不能靠文本匹配判在线，要用 returncode
- **编码坑**：Windows ping 输出 GBK，需显式转码
- **抗抖动设计**：down_threshold 参数，离线 2 次才告警，避免瞬时抖动误报

## 免责声明

本项目供学习/实验用途，请用于你拥有权限的网络环境。