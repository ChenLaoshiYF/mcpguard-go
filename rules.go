package main

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

// Finding 一条检测发现
type Finding struct {
	RuleID   string `json:"rule_id"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
	Source   string `json:"source"`
	Excerpt  string `json:"excerpt"`
}

// Rule 一条规则
type Rule struct {
	ID          string
	Name        string
	Severity    string
	Description string
	Check       func(text string) []string
}

// RuleEngine 规则引擎
type RuleEngine struct {
	rules []Rule
}

func (e *RuleEngine) Register(r Rule) {
	e.rules = append(e.rules, r)
}

func (e *RuleEngine) Scan(text, source string) []Finding {
	if text == "" {
		return nil
	}
	var findings []Finding
	for _, r := range e.rules {
		// 单条规则异常不影响整体（等价 Python 版 try/except）
		hits := func() (out []string) {
			defer func() { recover() }()
			return r.Check(text)
		}()
		for _, h := range hits {
			findings = append(findings, Finding{
				RuleID:   r.ID,
				Severity: r.Severity,
				Title:    r.Name,
				Detail:   r.Description,
				Source:   source,
				Excerpt:  truncate(h, 200),
			})
		}
	}
	return findings
}

func (e *RuleEngine) Rules() []Rule { return e.rules }

func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n])
}

// ---------------------------------------------------------------------------
// 规则数据（与 Python 版一一对应）
// ---------------------------------------------------------------------------

// Unicode 隐形字符：私有区（U+E0000–U+E007F）、零宽字符、Bidi 控制字符等
var hiddenUnicodeRe = regexp.MustCompile(
	"[\U000E0000-\U000E007F\u200B\u200C\u200D\u2060\uFEFF\u00AD" +
		"\u200E\u200F\u202A\u202B\u202C\u202D\u202E\u2066\u2067\u2068\u2069" +
		"\u061C\u034F]",
)

// 同形字映射：西里尔 / 拉丁扩展 / 数学字母数字符号
var homoglyphMap = buildHomoglyphMap()

func buildHomoglyphMap() map[rune]rune {
	m := map[rune]rune{
		// 西里尔
		'\u0430': 'a', '\u0435': 'e', '\u043E': 'o', '\u0440': 'p',
		'\u0441': 'c', '\u0445': 'x', '\u0456': 'i', '\u0458': 'j',
		'\u0432': 'b', '\u043D': 'h', '\u043A': 'k', '\u043C': 'm',
		'\u0410': 'A', '\u0415': 'E', '\u041E': 'O', '\u0420': 'P',
		'\u0421': 'C', '\u0425': 'X', '\u0433': 'r', '\u0455': 's',
		// 拉丁扩展
		'\u00E0': 'a', '\u00E1': 'a', '\u00E2': 'a', '\u00E4': 'a',
		'\u00E9': 'e', '\u00E8': 'e', '\u00EA': 'e', '\u00EB': 'e',
		'\u00ED': 'i', '\u00EC': 'i', '\u00EE': 'i', '\u00EF': 'i',
		'\u00F3': 'o', '\u00F2': 'o', '\u00F4': 'o', '\u00F6': 'o',
		'\u00FC': 'u', '\u00F9': 'u', '\u00FB': 'u', '\u00E7': 'c',
	}
	// 数学字母数字符号（U+1D400–U+1D7FF）
	lower := "abcdefghijklmnopqrstuvwxyz"
	for i, ch := range lower {
		m[rune(0x1D41A+i)] = ch            // 数学粗体小写
		m[rune(0x1D400+i)] = rune(ch - 32) // 数学粗体大写
		m[rune(0x1D4D0+i)] = ch            // 数学斜体小写
		m[rune(0x1D608+i)] = ch            // 数学无衬线粗体小写
		m[rune(0x1D622+i)] = ch            // 数学无衬线斜体小写
	}
	return m
}

// 同形字归一化后要匹配的攻击关键词
var homoglyphTriggers = []string{
	"ignore", "previous", "instructions", "system prompt", "override",
	"忽略", "指令", "规则", "忘记", "现在开始", "你扮演", "你是",
	"exfiltrat", "send to", "cc ", "bcc ", "new prime directive",
}

// 指令覆盖模式
var ignorePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|rules)`),
	regexp.MustCompile(`(?i)ignore\s+everything\s+(you|i|we)\s+`),
	regexp.MustCompile(`忽略(之前|以上|先前|前面).{0,6}(指令|指示|规则|要求)`),
	regexp.MustCompile(`(?i)disregard\s+(all\s+)?((previous|prior|above)\s+)?(instruction|rule|prompt)s?`),
	regexp.MustCompile(`忘记|忘掉.{0,6}(之前|以上|所有|一切).{0,6}(指令|提示|规则|要求|内容)`),
	regexp.MustCompile(`(?i)override\s+(the\s+)?system\s+prompt`),
	regexp.MustCompile(`(?i)you\s+are\s+now\s+`),
	regexp.MustCompile(`(?i)new\s+prime\s+directive`),
	regexp.MustCompile(`从现在起.{0,12}(你是|扮演|忘记|不再)`),
	regexp.MustCompile(`你不再是.{0,12}(AI|助手|机器人|模型)`),
	regexp.MustCompile(`输出你(收到|的).{0,6}(系统|所有|全部).{0,4}(指令|提示|prompt)`),
	regexp.MustCompile(`(复述|泄露|透露|展示).{0,8}(系统提示|system prompt|系统指令)`),
}

// 角色扮演注入（v0.3.0 同步）
var roleplayPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(从现在开始|从现在起|接下来).{0,10}(你是|你扮演|你将扮演|请扮演|假装你是)`),
	regexp.MustCompile(`(?i)(你不再|你不是|忘记你).{0,8}(AI助手|AI 助手|语言模型|assistant|chatbot)`),
	regexp.MustCompile(`(?i)you\s+are\s+(now\s+)?(no\s+longer\s+)?(an?\s+)?(assistant|chatbot|ai|llm)`),
	regexp.MustCompile(`(?i)(act|behave|pretend|roleplay)\s+(as|like)\s+(an?\s+)?(hacker|coder|admin|root|terminal)`),
	regexp.MustCompile(`(扮演|假装|模拟).{0,8}(黑客|管理员|root|终端|系统)`),
	regexp.MustCompile(`(?i)(system\s+prompt|instructions?)\s+(is\s+)?(now|replaced|overridden)`),
	regexp.MustCompile(`(?i)new\s+(instructions?|rules|directives?)\s+(apply|take\s+effect)`),
}

// 多语言指令覆盖（v0.3.0 同步，日/韩）
var i18nOverridePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(指示|命令|プロンプト).{0,8}(無視|無視して|無視しろ)`),
	regexp.MustCompile(`(?i)(これまでの|以前の).{0,6}(指示|命令).{0,8}(無視|すべて)`),
	regexp.MustCompile(`(?i)(지시|명령|프롬프트).{0,8}(무시|무시하고|무시해)`),
	regexp.MustCompile(`(?i)(이전|지금까지).{0,6}(지시|명령).{0,6}(무시|전부)`),
}

// 危险路径
var dangerousPaths = []string{
	`[/\\]\.ssh[/\\]`,
	`[/\\]\.aws[/\\]`,
	`[/\\]\.git[/\\]config`,
	`\.env\b`,
	`\bid_rsa\b`,
	`\bid_ed25519\b`,
	`credentials\b`,
	`\.pem\b`,
	`access[_-]?token`,
	`api[_-]?token`,
	`bearer[_-]?token`,
	`api[_-]?key\b`,
	`secret[_-]?key\b`,
	`client[_-]?secret\b`,
	`AWS[_A-Z]*SECRET`,
	`/etc/passwd\b`,
}

// 危险 shell 模式
// 注意：Go raw string（反引号）内不能直接写反引号，含 ` 的模式改用双引号字符串
var dangerousShell = []*regexp.Regexp{
	regexp.MustCompile(`(?i)curl[^\n]{0,60}\|\s*(ba)?sh`),
	regexp.MustCompile(`(?i)wget[^\n]{0,60}\|\s*(ba)?sh`),
	regexp.MustCompile(`(?i)rm\s+-rf\s+[/~]?\.?(/|\*|home|root)`),
	regexp.MustCompile(`(?i)rm\s+-rf\s+~/\\?`),
	regexp.MustCompile(`(?i)nc\s+-[^\n]*\s+(-e|-c)\s+`),
	regexp.MustCompile(`(?i)base64\s+[^\n]{0,40}-d`),
	// eval 与命令替换
	regexp.MustCompile("(?i)\\beval\\s*\\(\\s*[\"'$]|\\beval\\s+\\$\\s*\\(|\\beval\\s+`"),
	regexp.MustCompile(`(?i)\$\s*\(\s*(curl|wget|iwr|irm)\s`),
	regexp.MustCompile("(?i)^`(curl|wget|bash|sh|python)\\s[^`]*`"),
	regexp.MustCompile(`(?i)iex\s*\(\s*(iwr|irm|invoke-webrequest|invoke-restmethod)`),
	regexp.MustCompile(`(?i)invoke-expression\s*[\(\s]`),
	regexp.MustCompile(`(?i)os\.system\s*\(|subprocess\.(run|call|Popen)\s*\(`),
	regexp.MustCompile(`(?i)\bexec\s*\(\s*["']`),
	// 分步执行：下载后执行
	regexp.MustCompile(`(?i)(curl|wget|iwr|irm)[^\n]{0,80}(-o|out-file)[^\n]{0,60}(&&|;|and).{0,20}(bash|sh|./|start)`),
}

// base64 长串
var b64Re = regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`)

// 可疑行为描述
var suspiciousBehavior = []*regexp.Regexp{
	regexp.MustCompile(`(?i)always\s+(bcc|cc|copy|send|forward)[^\n]{0,40}(to|@)`),
	regexp.MustCompile(`(?i)without\s+(asking|telling|informing|notifying)[^\n]{0,40}(user|human)`),
	regexp.MustCompile(`静默[^\n]{0,10}(发送|抄送|上传|转发|删除)`),
	regexp.MustCompile(`(静默|暗中|偷偷|背着你|不通知|无需确认)[^\n]{0,12}(发送|上传|执行|提交|转发|删除)`),
	regexp.MustCompile(`(?i)do\s+not\s+(tell|inform|mention)\b[^\n]{0,60}(user|human|author|client)`),
	regexp.MustCompile(`(?i)(exfiltrat\w*\s+(data|content|files?|logs|info))|((data|content|files?|logs|info)\s+to\s+.{0,40}(exfiltrat))`),
	regexp.MustCompile(`(?i)steal|phish`),
}

// 密码赋值形态
var passwordAssignRe = regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[=:]\s*[^\s,;"'\n]{1,60}`)

// ---------------------------------------------------------------------------
// 各规则实现
// ---------------------------------------------------------------------------

func checkHiddenUnicode(text string) []string {
	var hits []string
	idx := hiddenUnicodeRe.FindAllStringIndex(text, -1)
	for i, m := range idx {
		if i >= 20 {
			break
		}
		start := max(0, m[0]-30)
		end := min(len(text), m[1]+30)
		hits = append(hits, "位置 "+itoa(m[0])+": …"+reprExcerpt(text[start:end])+"…")
	}
	return hits
}

func checkHomoglyph(text string) []string {
	var hits []string
	hasSuspicious := false
	for _, ch := range text {
		if _, ok := homoglyphMap[ch]; ok {
			hasSuspicious = true
			break
		}
	}
	if !hasSuspicious {
		return hits
	}
	normalized := normalizeHomoglyphs(text)
	lowered := strings.ToLower(normalized)
	for _, trigger := range homoglyphTriggers {
		idx := strings.Index(lowered, trigger)
		for idx != -1 && len(hits) < 20 {
			start := max(0, idx-25)
			end := min(len(text), idx+len(trigger)+25)
			hits = append(hits, "位置 "+itoa(idx)+": …"+text[start:end]+"…")
			next := strings.Index(lowered[idx+1:], trigger)
			if next == -1 {
				break
			}
			idx = idx + 1 + next
		}
	}
	return hits
}

// 归一化：把可疑字符翻译成 ASCII
func normalizeHomoglyphs(text string) string {
	var b strings.Builder
	for _, ch := range text {
		if repl, ok := homoglyphMap[ch]; ok {
			b.WriteRune(repl)
		} else {
			b.WriteRune(ch)
		}
	}
	return b.String()
}

func checkBase64(text string) []string {
	var hits []string
	for _, m := range b64Re.FindAllStringIndex(text, -1) {
		cand := text[m[0]:m[1]]
		// 过滤明显普通长单词（含小写长串多半不是 b64）
		if regexp.MustCompile(`[a-z]{6,}`).MatchString(cand) {
			continue
		}
		// 过滤 data:image/...;base64, 图片数据
		before := text[max(0, m[0]-60):m[0]]
		if regexp.MustCompile(`(?i)data:\s*image/|data:\s*[a-z]+/[a-z+.-]+;base64,`).MatchString(before) {
			continue
		}
		if len(hits) >= 20 {
			break
		}
		ex := cand
		if len(ex) > 60 {
			ex = ex[:60]
		}
		hits = append(hits, "位置 "+itoa(m[0])+": "+ex+"…")
	}
	return hits
}

func checkInstructionOverride(text string) []string {
	var hits []string
	for _, pat := range ignorePatterns {
		for _, m := range pat.FindAllStringIndex(text, -1) {
			if len(hits) >= 20 {
				return hits
			}
			start := max(0, m[0]-25)
			end := min(len(text), m[1]+25)
			hits = append(hits, "位置 "+itoa(m[0])+": …"+text[start:end]+"…")
		}
	}
	return hits
}

func checkDangerousPaths(text string) []string {
	var hits []string
	for _, pat := range dangerousPaths {
		re := regexp.MustCompile("(?i)" + pat)
		for _, m := range re.FindAllStringIndex(text, -1) {
			if len(hits) >= 20 {
				return hits
			}
			start := max(0, m[0]-20)
			end := min(len(text), m[1]+20)
			hits = append(hits, "位置 "+itoa(m[0])+": …"+text[start:end]+"…")
		}
	}
	return hits
}

func checkPasswordAssignment(text string) []string {
	var hits []string
	for _, m := range passwordAssignRe.FindAllStringIndex(text, -1) {
		if len(hits) >= 10 {
			break
		}
		start := max(0, m[0]-20)
		end := min(len(text), m[1]+20)
		hits = append(hits, "位置 "+itoa(m[0])+": …"+text[start:end]+"…")
	}
	return hits
}

func checkDangerousShell(text string) []string {
	var hits []string
	for _, pat := range dangerousShell {
		for _, m := range pat.FindAllStringIndex(text, -1) {
			if len(hits) >= 20 {
				return hits
			}
			start := max(0, m[0]-25)
			end := min(len(text), m[1]+25)
			hits = append(hits, "位置 "+itoa(m[0])+": …"+text[start:end]+"…")
		}
	}
	return hits
}

func checkSuspiciousBehavior(text string) []string {
	var hits []string
	for _, pat := range suspiciousBehavior {
		for _, m := range pat.FindAllStringIndex(text, -1) {
			if len(hits) >= 20 {
				return hits
			}
			start := max(0, m[0]-25)
			end := min(len(text), m[1]+25)
			hits = append(hits, "位置 "+itoa(m[0])+": …"+text[start:end]+"…")
		}
	}
	return hits
}

func checkRoleplay(text string) []string {
	var hits []string
	for _, pat := range roleplayPatterns {
		for _, m := range pat.FindAllStringIndex(text, -1) {
			if len(hits) >= 20 {
				return hits
			}
			start := max(0, m[0]-25)
			end := min(len(text), m[1]+25)
			hits = append(hits, "位置 "+itoa(m[0])+": …"+text[start:end]+"…")
		}
	}
	return hits
}

func checkI18nOverride(text string) []string {
	var hits []string
	for _, pat := range i18nOverridePatterns {
		for _, m := range pat.FindAllStringIndex(text, -1) {
			if len(hits) >= 20 {
				return hits
			}
			start := max(0, m[0]-25)
			end := min(len(text), m[1]+25)
			hits = append(hits, "位置 "+itoa(m[0])+": …"+text[start:end]+"…")
		}
	}
	return hits
}

// ---------------------------------------------------------------------------
// 引擎构建
// ---------------------------------------------------------------------------

func buildDefaultEngine() *RuleEngine {
	e := &RuleEngine{}
	e.Register(Rule{"UNI-001", "Unicode 隐形字符", "high",
		"检测到不可见 Unicode 字符（私有区/零宽字符/双向文本控制符），可能用于隐藏恶意指令以规避人工审查。",
		checkHiddenUnicode})
	e.Register(Rule{"B64-001", "可疑 base64 长串", "medium",
		"检测到疑似 base64 编码的长字符串，可能用于混淆指令内容，建议解码后人工确认。",
		checkBase64})
	e.Register(Rule{"INJ-001", "指令覆盖模式", "critical",
		"检测到试图覆盖/忽略原有指令的表述（如 ignore previous instructions），这是提示注入与工具投毒的核心特征。",
		checkInstructionOverride})
	e.Register(Rule{"PTH-001", "敏感路径引用", "high",
		"检测到对敏感文件路径的引用（SSH 密钥、AWS 凭据、token 等），存在被利用进行凭据窃取的风险。",
		checkDangerousPaths})
	e.Register(Rule{"SHL-001", "危险 shell 模式", "critical",
		"检测到管道执行远程脚本、危险删除、反向 shell 等模式。",
		checkDangerousShell})
	e.Register(Rule{"PWD-001", "密码赋值形态", "info",
		"检测到 password= / password: 形式的赋值（可能是配置中的明文密码），仅提示注意，不作高危判定。",
		checkPasswordAssignment})
	e.Register(Rule{"BH-001", "可疑工具行为描述", "high",
		"检测到静默操作、自动外发数据、绕过用户知情等异常行为描述，符合已知工具投毒攻击特征。",
		checkSuspiciousBehavior})
	e.Register(Rule{"HMG-001", "同形字混淆 (homoglyph)", "high",
		"检测到使用视觉相近的 Unicode 字符冒充 ASCII 字母（如西里尔 а 冒充 a），用于绕过关键词过滤隐藏恶意指令。",
		checkHomoglyph})
	e.Register(Rule{"INJ-002", "角色扮演注入", "critical",
		"检测到诱导模型切换角色/行为的表述（如“从现在开始你是黑客”），属于提示注入的语义变体，可绕过关键词过滤。",
		checkRoleplay})
	e.Register(Rule{"INJ-003", "多语言指令覆盖", "high",
		"检测到日语/韩语的指令覆盖表述（無視して / 무시하고），多语言提示注入正成为国际工具投毒的趋势手法。",
		checkI18nOverride})
	return e
}

// ---------------------------------------------------------------------------
// 工具函数
// ---------------------------------------------------------------------------

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func reprExcerpt(s string) string {
	// 近似 Python repr：控制字符转义（简化实现）
	var b strings.Builder
	for _, ch := range s {
		switch ch {
		case '\n':
			b.WriteString(`\n`)
		case '\t':
			b.WriteString(`\t`)
		case '\r':
			b.WriteString(`\r`)
		default:
			b.WriteRune(ch)
		}
	}
	return b.String()
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
