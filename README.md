# 明棱 mcpguard (Go)

AI Agent 安全扫描器，Go 实现版。检测 MCP 工具描述与 skill 文件中的投毒特征：提示注入、同形字混淆、Unicode 隐形字符、危险 shell、凭据泄露。

**零第三方依赖 · 单二进制 · 毫秒级启动 · 三平台交叉编译**

## 为什么用 Go 写

| 特性 | mcpguard (Go) | 其他实现 |
|------|--------------|---------|
| 分发形态 | 单个可执行文件 3.3MB | 需 Python 运行时 / 打包 9MB+ |
| 启动速度 | 毫秒级 | 数百毫秒 |
| 依赖 | 纯 Go 标准库（regexp） | 需 pip 安装 |
| 平台 | Windows / macOS / Linux 一条命令交叉编译 | 需各平台打包 |
| 嵌入 | 可被子进程调用，任意语言 MCP 客户端可接 | — |

## 检测规则

与 Python 版同一套规则引擎，8 类检测：

| ID | 规则 | 严重度 | 检测内容 |
|----|------|--------|---------|
| UNI-001 | Unicode 隐形字符 | high | 私有区、零宽字符、Bidi 控制符（可隐藏指令） |
| B64-001 | 可疑 base64 长串 | medium | 疑似编码混淆的指令内容 |
| INJ-001 | 指令覆盖模式 | **critical** | "ignore previous instructions" 等提示注入核心特征 |
| PTH-001 | 敏感路径引用 | high | SSH 密钥、AWS 凭据、token 文件路径 |
| SHL-001 | 危险 shell 模式 | **critical** | curl\|sh、rm -rf、反向 shell、eval、PowerShell IEX |
| PWD-001 | 密码赋值形态 | info | password= 明文赋值（仅提示） |
| BH-001 | 可疑工具行为描述 | high | 静默外发、绕过用户知情、exfiltrate |
| HMG-001 | 同形字混淆 | high | 西里尔/数学字母体冒充 ASCII 绕过过滤 |

报告输出含脱敏：sk- API key、GitHub token、SSH 私钥块、JWT 自动替换为 `***`。

## 构建

```bash
# Windows
GOOS=windows GOARCH=amd64 go build -o mcpguard.exe .

# Linux / macOS
GOOS=linux  GOARCH=amd64 go build -o mcpguard-linux .
GOOS=darwin GOARCH=arm64 go build -o mcpguard-macos .
```

无需任何第三方模块（`go.mod` 只有 module 声明）。

## 使用

```bash
mcpguard                          # 扫描本机默认位置（MCP 配置 + skill 目录）
mcpguard -path ./my-config.json   # 扫描指定文件
mcpguard -path ./skills,./config  # 扫描多个路径（逗号分隔）
mcpguard -json                    # JSON 输出（CI 友好）
mcpguard -exit-code               # 存在 critical/high 时退出码 1（CI 门禁）
mcpguard -version                 # 显示版本
```

### CI 集成示例

```yaml
- name: Scan for tool poisoning
  run: mcpguard -path . -json -exit-code
```

## 退出码

- `0`：无 critical/high 发现（或未使用 `-exit-code`）
- `1`：存在 critical/high 级风险（仅 `-exit-code` 模式）

## 隐私

完全本地运行，不联网、不上报、零遥测。

## License

MIT
