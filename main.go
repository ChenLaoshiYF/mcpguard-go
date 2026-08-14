package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

const version = "0.1.0"

func main() {
	var (
		pathsStr = flag.String("path", "", "要扫描的路径（逗号分隔，默认扫本机 MCP 配置与 skill 目录）")
		jsonOut  = flag.Bool("json", false, "JSON 输出（CI 友好）")
		exitCode = flag.Bool("exit-code", false, "存在 critical/high 时退出码 1")
		showVer  = flag.Bool("version", false, "显示版本")
	)
	flag.Parse()

	if *showVer {
		fmt.Printf("mcpguard %s (Go)\n", version)
		return
	}

	var extra []string
	if *pathsStr != "" {
		for _, p := range strings.Split(*pathsStr, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				extra = append(extra, p)
			}
		}
	}

	engine := buildDefaultEngine()
	targets := scanAll(extra)
	report := buildReport(targets, engine)

	if *jsonOut {
		fmt.Println(report.toJSON())
	} else {
		fmt.Print(report.toText())
	}

	if *exitCode {
		for _, t := range report.Targets {
			for _, f := range t.Findings {
				if f.Severity == "critical" || f.Severity == "high" {
					os.Exit(1)
				}
			}
		}
	}
}
