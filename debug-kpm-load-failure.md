# [OPEN] kpm-load-failure

## 背景
- 现象：`svc_monitor` KPM 已加载，但“好像用不了”
- 目标：确认故障点是在模块加载、`ctl0` 控制、hook 安装、事件输出，还是设备/权限环境

## 初始假设
- 假设 1：模块虽然被加载，但 `ctl0` 命令没有正确路由到 `svc_monitor`
- 假设 2：模块初始化执行了，但 tier1 hook 或关键符号解析失败，导致监控不可用
- 假设 3：模块正常工作，但用户侧使用的 `kpatch` key、模块名或命令格式不匹配
- 假设 4：事件已产生，但输出链路异常，例如 `drain` JSON、二进制事件文件或权限路径有问题
- 假设 5：Android 内核/SELinux/机型差异导致某些 hook API 调用失败

## 计划
- 先检查设备连接、root、`kpatch` 可执行路径和 `ctl0 status`
- 再看内核日志与模块日志
- 再验证最小命令链路：`status -> enable -> set_nrs -> drain`
- 如果证据指向代码问题，再做最小插桩或修复

## 已收集证据
- `adb devices` 正常，`su -c id` 显示 root，上位机与设备连接正常
- `dmesg` 明确显示：`svc_monitor v8.2.0: init, installing hooks...`、`tier1 installed 46/46 hooks`、`do_filp_open hook installed`
- `/data/adb/ap/bin/` 目录中不存在可执行 `kpatch`，直接执行旧命令会报 `inaccessible or not found`
- 设备存在 APatch 包 `me.bmax.apatch`
- 在该设备上执行 `adb shell su -c "truncate XiaoLu0129 module ctl0 svc_monitor 'status'"` 后，`/data/local/tmp/svc_out.json` 返回有效 JSON
- 已验证最小链路：`enable -> set_nrs 63 -> drain 20` 成功，并采到真实 `read(63)` 事件

## 当前结论
- 根因不是 KPM 模块未加载，也不是 hook 安装失败
- 根因是项目中的 MCP / 文档 / 启动脚本默认写死旧控制入口 `/data/adb/ap/bin/kpatch ... kpm ctl0 ...`
- 当前设备实际可用控制入口是 `truncate <SuperKey> module ctl0 <module> '<cmd>'`

## 已做修复
- MCP Server 改为自动探测多个 ctl0 入口，并优先复用已探测成功的模板
- `start.sh` 改为自动探测 ctl0 入口，而不是写死旧路径
- Skill/README 中的示例命令更新为当前设备可用写法，并补充“入口因设备而异”的说明
