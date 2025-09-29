## 2tina SQL 注入自动化（Burp Suite 扩展）

2tina SQL 注入自动化是一个基于 Burp Suite + Jython 的被动/半自动 SQL 注入探测扩展。在授权的安全测试中，它可对 URL 参数、表单参数以及 JSON 结构进行轻量探测，并支持外部 payload 文件自定义与一键保存/加载。

> 二次开发说明：本项目在开源项目 xiaSql 的基础上进行功能增强与界面优化（二开来源：[CocoHall/xiaSql](https://github.com/CocoHall/xiaSql)).

---

### 主要特性

- 被动/半自动探测
  - 可勾选监控 Repeater 或 Proxy 流量，发包即测。
- JSON 深度遍历
  - 支持 URL/Form、JSON 字符串/数字/数组/嵌套对象的遍历注入测试。
- 外部 Payload 管理
  - 默认使用 `payload.txt`；可在插件侧栏直接编辑并保存，启动时自动加载。
- 变化/报错/耗时提示
  - 结果表格展示包长变化、错误特征、响应时间等关键信息。
- 内存友好
  - 可配置“最大日志条数”，自动裁剪旧记录，适合长时间运行。
- 便捷白名单
  - 域名与参数白名单（正则/逗号分隔）避免对不必要目标发起检测。

---

### 运行环境

- Burp Suite（Pro/Community 皆可）
- Jython 2.7.x（Standalone 或 Burp 内置 Jython 插件）
- Java 8+（随 Burp 发行版即可）

---

### 安装步骤（Jython）

1) 安装 Jython

- 下载 `jython-installer-2.7.x.jar`，执行安装或直接使用 standalone。
- 在 Burp 中打开 Extender → Options → Python Environment：
  - 如果使用 standalone：选择 `jython-standalone-2.7.x.jar` 路径。
  - 如果已安装到本地：选择对应的 `jython.jar`。

2) 加载扩展

- 打开 Burp → Extender → Extensions → Add：
  - Extension type 选择 Python
  - 选择本项目中的 `xiaSql.py`（或你的二开版本文件）
  - 成功后在 Extender 输出窗口可见启动横幅与 `Default Payload File` 提示。

3) 首次启动

- 若当前目录没有 `payload.txt`，扩展会自动创建并写入一批常用 payload 示例。
- 侧栏可看到：监控选项、字符集切换、白名单、最大日志条数、Payload 文件路径、Payload 列表编辑区与保存按钮。

---

### 使用方法

1) 选择监听源

- 在侧栏勾选“监控 Repeater”或“监控 Proxy”。

2) 配置白名单与字符集

- 域名白名单：正则或字符串，逗号分隔；匹配则不检测。
- 参数白名单：逗号分隔；命中则不注入该参数。
- URL 字符集：UTF-8/GBK（当存在 URL 编码 JSON 时尤为关键）。

3) 配置 Payload

- `Payload 文件路径` 指向 `payload.txt` 或你的自定义文件。
- 在 `Payload 列表` 中编辑内容后点击“保存Payload”会写回文件并自动加载。
- 若 `payload.txt` 为空，扩展会退回内置基础 payload 集合。

4) 开始测试

- 在授权范围内发起请求（Proxy/Repeater）。
- 左侧“原始请求列表”展示每次被检测的接口与状态；点击一行可在下表查看该接口下每个参数/值的探测记录、包长变化、用时与响应码，并在底部查看具体请求/响应。

---

### Payload 机制

- 外部优先、内置兜底。
- 对数字/排序语义的参数，会自动补充 `-1`、`-0`、`,111`、`,1` 等上下文 payload。
- 对 JSON 字符串/数字/数组/嵌套结构逐一遍历注入，尽量模拟最小扰动增量。

---

### 性能与稳定性建议

- 将“最大日志条数”设置在合适范围（默认 300），长时间扫描时可有效控内存。
- 合理配置域名/参数白名单，减少对不必要目标与噪声参数的检测。
- 推荐在 Repeater 验证重要接口，再切到 Proxy 扩大覆盖面。

---

### 安全与合法性声明

仅可用于取得明确授权的安全测试。测试前请确保：

- 已获得目标方书面授权；
- 已与业务方约定测试范围、时间窗口与影响控制措施；
- 任何输出数据仅用于安全评估，不得用于非法用途或对生产环境造成损害。

使用本扩展造成的任何后果由使用者自行承担。

---

### 致谢与二开来源

本项目在以下开源项目基础上二次开发并致谢：

- xiaSql（Python 魔改版）：[https://github.com/CocoHall/xiaSql](https://github.com/CocoHall/xiaSql)

---

### 常见问题（FAQ）

Q: 为什么某些请求不检测？

- 命中了域名白名单或参数白名单；
- 判定为静态资源（如 `.png/.css/.js` 等后缀）；
- Burp 无响应或目标服务未返回可解析响应体。

Q: JSON 里是 URL 编码的对象该怎么处理？

- 在“URL 字符集”处切换 UTF-8/GBK，使编码/解码与服务端一致。

Q: Payload 有没有推荐模板？

- 初始自动生成的 `payload.txt` 已涵盖常见闭合、联合查询、延时与多数据库语法，可按需增删。每行一个 payload，允许 `# // --` 开头的注释。


