package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

type block struct {
	location   string
	statements int
	count      int64
}

func main() {
	if len(os.Args) < 3 {
		fatal("usage: mergecoverage OUTPUT INPUT...")
	}
	mode := ""
	blocks := make(map[string]block)
	for _, path := range os.Args[2:] {
		file, err := os.Open(path)
		if err != nil {
			fatal("open %s: %v", path, err)
		}
		scanner := bufio.NewScanner(file)
		if !scanner.Scan() || !strings.HasPrefix(scanner.Text(), "mode: ") {
			_ = file.Close()
			fatal("%s has no coverage mode", path)
		}
		inputMode := strings.TrimPrefix(scanner.Text(), "mode: ")
		if mode == "" {
			mode = inputMode
		} else if inputMode != mode {
			_ = file.Close()
			fatal("%s uses coverage mode %s, not %s", path, inputMode, mode)
		}
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) != 3 {
				_ = file.Close()
				fatal("%s has an invalid coverage record", path)
			}
			statements, err := strconv.Atoi(fields[1])
			if err != nil {
				_ = file.Close()
				fatal("%s has an invalid statement count", path)
			}
			count, err := strconv.ParseInt(fields[2], 10, 64)
			if err != nil {
				_ = file.Close()
				fatal("%s has an invalid execution count", path)
			}
			current := blocks[fields[0]]
			current.location = fields[0]
			current.statements = statements
			current.count += count
			if mode == "set" && current.count > 1 {
				current.count = 1
			}
			blocks[fields[0]] = current
		}
		if err := scanner.Err(); err != nil {
			_ = file.Close()
			fatal("read %s: %v", path, err)
		}
		if err := file.Close(); err != nil {
			fatal("close %s: %v", path, err)
		}
	}

	locations := make([]string, 0, len(blocks))
	for location := range blocks {
		locations = append(locations, location)
	}
	sort.Strings(locations)
	var result strings.Builder
	fmt.Fprintf(&result, "mode: %s\n", mode)
	for _, location := range locations {
		entry := blocks[location]
		fmt.Fprintf(&result, "%s %d %d\n", entry.location, entry.statements, entry.count)
	}
	if err := os.WriteFile(os.Args[1], []byte(result.String()), 0o644); err != nil {
		fatal("write %s: %v", os.Args[1], err)
	}
}

func fatal(format string, values ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", values...)
	os.Exit(1)
}
