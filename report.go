package main

import (
	"encoding/json"
	"regexp"
	"strings"
)

// TargetReport 单个目标的扫描结果
type TargetReport struct {
	Name     string    `json:"name"`
	Path     string    `json:"path"`
	Score    int       `json:"score"`
	Findings []Finding `json:"findings"`
}

// Report 完整报告
type Report struct {
	Targets []TargetReport `json:"targets"`
}

// 脱敏：密钥模式替换为 ***
var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(sk-[A-Za-z0-9_-]{20,})`),
	regexp.MustCompile(`(?i)(ghp_[A-Za-z0-9]{30,})`),
	regexp.MustCompile(`(?i)(github_pat_[A-Za-z0-9_]{20,})`),
	regexp.MustCompile(`(?i)(-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----)`),
	regexp.MustCompile(`(?i)(AIza[A-Za-z0-9_-]{20,})`),
	regexp.MustCompile(`(?i)(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})`),
	regexp.MustCompile(`(?i)(password\s*[=:]\s*["'][^"']{6,}["']|password\s*[=:]\s*[^\s,;"']{6,})`),
}

func redact(s string) string {
	out := s
	for _, re := range secretPatterns {
		out = re.ReplaceAllString(out, "***")
	}
	return out
}

// 评分：100 - 扣分
func severityScore(findings []Finding) int {
	if len(findings) == 0 {
		return 100
	}
	score := 100
	for _, f := range findings {
		w := map[string]int{
			"critical": 40, "high": 20, "medium": 8, "low": 3, "info": 1,
		}[f.Severity]
		if w == 0 {
			w = 1
		}
		score -= w
	}
	if score < 0 {
		return 0
	}
	return score
}

// buildReport 对目标列表执行扫描，生成报告
func buildReport(targets []ScanTarget, engine *RuleEngine) Report {
	var rep Report
	for _, t := range targets {
		findings := engine.Scan(t.Content, t.Name+" ("+t.Path+")")
		rep.Targets = append(rep.Targets, TargetReport{
			Name:     t.Name,
			Path:     redact(t.Path),
			Score:    severityScore(findings),
			Findings: findings,
		})
	}
	return rep
}

// toJSON 序列化报告（脱敏所有敏感字段）
func (r Report) toJSON() string {
	for i := range r.Targets {
		r.Targets[i].Path = redact(r.Targets[i].Path)
		for j := range r.Targets[i].Findings {
			f := &r.Targets[i].Findings[j]
			f.Source = redact(f.Source)
			f.Excerpt = redact(f.Excerpt)
			f.Detail = redact(f.Detail)
		}
	}
	b, _ := json.MarshalIndent(r, "", "  ")
	return string(b)
}

// toText 文本报告
func (r Report) toText() string {
	var b strings.Builder
	b.WriteString("明棱 MCPGuard - AI Agent 安全扫描报告\n")
	b.WriteString("======================================\n\n")
	critical := 0
	for _, t := range r.Targets {
		b.WriteString("[")
		b.WriteString(itoa(t.Score))
		b.WriteString("/100] ")
		b.WriteString(t.Name)
		b.WriteString("\n")
		for _, f := range t.Findings {
			if f.Severity == "critical" {
				critical++
			}
			b.WriteString("  [")
			b.WriteString(strings.ToUpper(f.Severity))
			b.WriteString("] ")
			b.WriteString(f.RuleID)
			b.WriteString(" ")
			b.WriteString(f.Title)
			b.WriteString("\n    ")
			b.WriteString(redact(f.Excerpt))
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
	b.WriteString("-------------------------------------------------\n")
	if critical > 0 {
		b.WriteString("结论：发现 ")
		b.WriteString(itoa(critical))
		b.WriteString(" 条 critical 级风险，建议人工核对后处理。\n")
	} else {
		b.WriteString("结论：未发现 critical 级风险。\n")
	}
	b.WriteString("注意：检测基于关键词规则，可能产生误报，请人工核对每一项发现。\n")
	return b.String()
}
