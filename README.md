# 海底观测网设备故障管理

这是一个只使用Python标准库和SQLite的模块化原型项目，默认端口为`8337`。领域对象包括站点、资产、链路、遥测、故障事件、恢复动作、出海任务和数据缺口。`app.py`只负责参数解析、依赖组装和服务生命周期，业务状态机与约束集中在`src/rules.py`。

## 模块结构

- `app.py`：命令行参数、依赖组装、启动和信号处理。
- `src/domain.py`：角色、领域异常、身份解析和实体数据结构。
- `src/rules.py`：状态机、角色权限、领域计算、冲突和跨对象校验。
- `src/repository.py`：SQLite建表、查询、事务、乐观锁、审计和幂等键。
- `src/service.py`：用例编排、离线记录合并、版本控制和审计写入。
- `src/http_api.py`：HTTP路由、JSON解析和统一错误响应。
- `src/audit.py`：实体操作审计时间线。
- `static/index.html`：最小演示页面。
- `tests/`：完整流程、规则和失败场景测试。

## 初始化与启动

```bash
python3 app.py --db ./data.db --port 8337
```

服务启动时自动建表。`--host`可修改监听地址，`--db`可指定其他SQLite文件。初始化服务不需要单独命令，首次启动即可访问：

```bash
curl http://127.0.0.1:8337/health
```

## 主要接口

- `GET /health`：健康检查。
- `GET /api/<kind>`：按对象类型查询，可用`?status=`过滤。
- `POST /api/<kind>`：创建对象；请求体为JSON。
- `GET /api/entities/<id>`：读取对象当前版本。
- `POST /api/entities/<id>/actions`：提交`{"action":"动作名","data":{...},"expected_version":数字}`。
- `GET /api/audit`：读取审计记录。

身份通过`X-User-Id`和`X-Role`请求头传入，角色和动作权限由规则引擎校验。## 核心流程

建立站点、资产和链路后记录遥测与故障事件，创建恢复动作并跟踪重启、备用链路、出海任务和数据缺口，最后关闭事件。遥测`revise`动作只接受更高修订号，用于处理迟到数据。

## 规则重点

- 同一资产和故障类型不能同时有多个活动事件。
- 恢复动作按`dedupe_key`防止重复执行。
- 事件解决前恢复动作、数据缺口和受影响资产必须达到可关闭状态。

## 备用通道上报额度

主链路中断后执行链路动作`activate_backup`切到备用通道。备用通道容量小，系统按故障事件轻重为该站各资产重新分配上报额度，额度保存在系统生成的`allocation`对象中（id为`allocation-<链路id>`）：

- 资产等级取其活动故障事件（`open`/`diagnosing`/`recovery_planned`/`recovering`）的最高严重度：`critical > high > medium > low > 无事件`；链路级或站点级事件覆盖该链路下所有资产。
- 按等级从高到低、同等级按资产id分配：额度够则`active`拿满；容量不足时低级别先`degraded`（拿剩余额度）或`queued`（额度为0，带`queue_position`排队），保证关键设备读数不被挤掉。
- 每个资产的需求额度为`report_rate`（缺省1）；备用容量取链路的`backup_capacity`，未填写时为主链路`capacity`的25%。
- 事件等级通过incident动作`change_severity`（数据`{"severity":"..."}`）调整；等级一变，或活动事件新建/解决/关闭/重开、备用期间新增资产，先前分配立即作废并整体重算，`epoch`递增；等级升高的设备会立刻把额度从低级别设备收回。
- 链路执行`restore`恢复后，分配复位为`normal`模式，全部资产按主链路容量`active`上报。
- 两名调度同时提交同一链路切换时，先写入者生效（SQLite `BEGIN IMMEDIATE` + 乐观锁）；后到者收到409，响应体`details`中带当前生效的分配，随后可通过`GET /api/allocations?link_id=<链路id>`查看。

## 测试

```bash
python3 -m unittest discover -s tests -v
```

## 局限

项目使用请求头模拟身份、SQLite单机持久化和简化状态机，适合原型演示和流程验证，不替代行业正式系统、设备控制系统或现场安全规程。
