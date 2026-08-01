package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

const module = "github.com/bearfire-dev/tailscale-railway-quic-bridge/"

type coverage struct {
	covered int
	total   int
}

func main() {
	if len(os.Args) != 2 {
		fatal("usage: checkcoverage PROFILE")
	}
	file, err := os.Open(os.Args[1])
	if err != nil {
		fatal("open coverage profile: %v", err)
	}
	defer file.Close()

	packages := make(map[string]coverage)
	scanner := bufio.NewScanner(file)
	if !scanner.Scan() || !strings.HasPrefix(scanner.Text(), "mode: ") {
		fatal("the coverage profile has no mode")
	}
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 3 {
			fatal("the coverage profile has an invalid record")
		}
		colon := strings.LastIndexByte(fields[0], ':')
		if colon < 0 {
			fatal("the coverage profile has an invalid record location")
		}
		slash := strings.LastIndexByte(fields[0][:colon], '/')
		if slash < 0 {
			fatal("the coverage profile has an invalid record location")
		}
		name := strings.TrimPrefix(fields[0][:slash], module)
		if !strings.HasPrefix(name, "cmd/") && !strings.HasPrefix(name, "internal/") {
			continue
		}
		statements, err := strconv.Atoi(fields[1])
		if err != nil {
			fatal("the coverage profile has an invalid statement count")
		}
		entry := packages[name]
		entry.total += statements
		if fields[2] != "0" {
			entry.covered += statements
		}
		packages[name] = entry
	}
	if err := scanner.Err(); err != nil {
		fatal("read coverage profile: %v", err)
	}

	names := make([]string, 0, len(packages))
	for name := range packages {
		names = append(names, name)
	}
	sort.Strings(names)
	var covered, total int
	failed := false
	strict := map[string]bool{
		"internal/config": true, "internal/protocol": true, "internal/transport": true,
		"internal/connector": true, "internal/edge": true, "internal/proxy": true,
		"internal/status": true,
	}
	for _, name := range names {
		entry := packages[name]
		covered += entry.covered
		total += entry.total
		rate := percent(entry)
		fmt.Printf("%-28s %6.1f%%\n", name, rate)
		if entry.covered == 0 || (strict[name] && rate < 85) {
			failed = true
		}
	}
	for name := range strict {
		if _, ok := packages[name]; !ok {
			fmt.Printf("%-28s missing from the coverage profile\n", name)
			failed = true
		}
	}
	overall := percent(coverage{covered: covered, total: total})
	fmt.Printf("%-28s %6.1f%%\n", "repository", overall)
	if overall < 80 {
		failed = true
	}
	if failed {
		fatal("coverage does not meet the required thresholds")
	}
}

func percent(value coverage) float64 {
	if value.total == 0 {
		return 0
	}
	return float64(value.covered) * 100 / float64(value.total)
}

func fatal(format string, values ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", values...)
	os.Exit(1)
}
