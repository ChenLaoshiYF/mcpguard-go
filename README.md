# 明棱 mcpguard (Go) - AI Agent 安全扫描器

Go 实现版：检测 MCP 工具描述与 skill 文件中的投毒特征（提示注入、同形字、Unicode 隐形字符、危险 shell、凭据泄露）。

## 特性

- **零第三方依赖**：纯 Go 标准库，`regexp` 实现全部 8 类检测规则
- **单二进制**：交叉编译一条命令，Windows/macOS/Linux 通用
- **毫秒级启动**：无 Python 解释器开销
- **规则与 Python 版一致**：UNI-001 / B64-001 / INJ-001 / PTH-001 / SHL-001 / PWD-001 / BH-001 / HMG-001

## 构建

```bash
# Windows
GOOS=windows GOARCH=amd64 go build -o mcpguard.exe .

# macOS / Linux
GOOS=darwin GOARCH=arm64 go build -o mcpguard .
GOOS=linux GOARCH=amd64 go build -o mcpguard .
```

## 使用

```bash
mcpguard                  # 扫描本机默认位置（MCP 配置 + skill 目录）
mcpguard -path ./dir      # 扫描指定路径
mcpguard -json            # JSON 输出（CI 友好）
mcpguard -exit-code       # 存在 critical/high 时退出码 1
```
