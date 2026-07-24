# recover + master 集成报告

## 集成方式
以 origin/recover/multiprocess-third-party-sets (c4d1edb) 为基础，
将 master (backup/master-pre-recover-merge = 45ad493) 的 6 个提交逐一评估后移植。

## 逐提交处理

| master 提交 | 处理 | 理由 |
|---|---|---|
| 1642e66 docs: 修复计划 | cherry-pick (0f50e51) | 文档无冲突 |
| 702858d QueryLogStore 跨 loop 安全 | cherry-pick (1b71f98) | recover 文件与分叉点一致，干净落地；多进程模式下 webui(主进程 loop) 与 worker 进程间不共享内存，单进程模式下同 loop，线程锁+Event 实现在各模式下均安全 |
| 57305e7 ECH 实例级缓存 | cherry-pick (e6c6ab4) | recover 仅删了一个未使用 helper，自动合并成功；实例级缓存在单/多进程模式下均正确 |
| 4f254cd 多线程架构(PortalWorker 线程池) | 跳过 | recover 已有多进程架构(core/multiprocess/ + FrontCache)，与 PortalWorker 线程池解决同一并发问题；两套并存会造成配置(runtime.workers vs multiprocess.workers)与运行路径冲突。以 recover 架构为准 |
| ceb74d7 reload 关会话 + aiodns 按 loop 过滤 | 跳过 | 该 fix 针对 PortalWorker._async_reload。recover 多进程 reload 通过整体重建 worker pool 处理(manager.py:95-134)，无此问题；单进程 RuntimeManager.stop 已调 close_shared_sessions。aiodns 按 loop 过滤在多进程架构下无意义(进程隔离) |
| 45ad493 reload 预检 | 跳过 | recover 多进程 reload 已具备等价语义：新 pool 构建失败时整体回滚(manager.py except 分支 stop+cleanup)，无半新半旧 |

## 验证
- 全量测试: 292 passed, 1 failed(已知环境性失败 test_webui_server_uses_current_event_loop, 缺 tags/geosite 外部数据)
