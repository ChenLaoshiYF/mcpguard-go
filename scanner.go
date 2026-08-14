package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// ScanTarget 一个扫描目标
type ScanTarget struct {
	Kind    string // dir / file
	Name    string
	Path    string
	Content string
}

// skill 文件扩展名白名单
var skillFileExts = map[string]bool{
	".md": true, ".txt": true, ".json": true, ".jsonl": true, ".yaml": true,
	".yml": true, ".py": true, ".js": true, ".ts": true, ".toml": true,
	".xml": true, ".html": true,
}

// 默认扫描位置：常见 MCP 配置 + skill 目录
func defaultPaths() []string {
	var paths []string
	home, err := os.UserHomeDir()
	if err != nil {
		return paths
	}
	if runtime.GOOS == "windows" {
		paths = append(paths,
			filepath.Join(home, ".claude", "claude_desktop_config.json"),
			filepath.Join(home, ".cursor", "mcp.json"),
			filepath.Join(home, ".config", "codeium", "windsurf", "mcp_config.json"),
			filepath.Join(home, ".mcp.json"),
		)
		// skill 目录（Claude Code 等）
		paths = append(paths,
			filepath.Join(home, ".claude", "skills"),
			filepath.Join(home, ".config", "claude", "skills"),
		)
	} else {
		paths = append(paths,
			filepath.Join(home, ".claude", "claude_desktop_config.json"),
			filepath.Join(home, ".config", "claude", "claude_desktop_config.json"),
			filepath.Join(home, ".mcp.json"),
		)
		paths = append(paths,
			filepath.Join(home, ".claude", "skills"),
			filepath.Join(home, ".config", "claude", "skills"),
		)
	}
	return paths
}

// scanFile 扫描单个文件（检查扩展名白名单）
func scanFile(path string, targets *[]ScanTarget) {
	ext := strings.ToLower(filepath.Ext(path))
	if !skillFileExts[ext] {
		return
	}
	// 跳过超大文件
	fi, err := os.Stat(path)
	if err != nil || fi.Size() > 256*1024 {
		return
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return
	}
	*targets = append(*targets, ScanTarget{
		Kind: "file", Name: filepath.Base(path), Path: path, Content: string(content),
	})
}

// scanDir 递归扫描目录（跳过 .git/.venv 等）
func scanDir(dir string, targets *[]ScanTarget) {
	skipDirs := map[string]bool{".git": true, ".venv": true, "venv": true,
		"node_modules": true, "__pycache__": true, "dist": true, "build": true,
		"models": true, ".idea": true, ".vscode": true}
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		scanFile(path, targets)
		return nil
	})
}

// scanAll 扫描全部目标，返回目标列表
func scanAll(extraPaths []string) []ScanTarget {
	var targets []ScanTarget
	// 显式指定路径优先
	if len(extraPaths) > 0 {
		for _, p := range extraPaths {
			fi, err := os.Stat(p)
			if err != nil {
				continue
			}
			if fi.IsDir() {
				scanDir(p, &targets)
			} else {
				scanFile(p, &targets)
			}
		}
		return targets
	}
	// 默认位置
	for _, p := range defaultPaths() {
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		if fi.IsDir() {
			scanDir(p, &targets)
		} else {
			scanFile(p, &targets)
		}
	}
	return targets
}
