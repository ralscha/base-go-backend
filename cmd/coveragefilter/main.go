package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type excludes []string

func (e *excludes) String() string {
	return strings.Join(*e, ",")
}

func (e *excludes) Set(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("exclude value cannot be empty")
	}
	*e = append(*e, value)
	return nil
}

func main() {
	var inputPath string
	var outputPath string
	var patterns excludes

	flag.StringVar(&inputPath, "in", "", "input coverage profile path")
	flag.StringVar(&outputPath, "out", "", "output coverage profile path")
	flag.Var(&patterns, "exclude", "substring to exclude from the coverage profile; may be repeated")
	flag.Parse()

	if err := run(inputPath, outputPath, patterns); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(inputPath string, outputPath string, patterns []string) error {
	if strings.TrimSpace(inputPath) == "" {
		return errors.New("-in is required")
	}
	if strings.TrimSpace(outputPath) == "" {
		return errors.New("-out is required")
	}

	inputFile, err := openCoverageInput(inputPath)
	if err != nil {
		return fmt.Errorf("open input profile: %w", err)
	}
	defer func() { _ = inputFile.Close() }()

	outputFile, err := createCoverageOutput(outputPath)
	if err != nil {
		return fmt.Errorf("create output profile: %w", err)
	}
	defer func() { _ = outputFile.Close() }()

	scanner := bufio.NewScanner(inputFile)
	writer := bufio.NewWriter(outputFile)
	defer func() { _ = writer.Flush() }()

	lineNumber := 0
	for scanner.Scan() {
		line := scanner.Text()
		lineNumber++

		if lineNumber == 1 {
			if _, err := writer.WriteString(line + "\n"); err != nil {
				return fmt.Errorf("write profile header: %w", err)
			}
			continue
		}

		if shouldExclude(line, patterns) {
			continue
		}

		if _, err := writer.WriteString(line + "\n"); err != nil {
			return fmt.Errorf("write profile line: %w", err)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read input profile: %w", err)
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("flush output profile: %w", err)
	}

	return nil
}

func openCoverageInput(path string) (*os.File, error) {
	cleanPath := filepath.Clean(strings.TrimSpace(path))

	return os.Open(cleanPath)
}

func createCoverageOutput(path string) (*os.File, error) {
	cleanPath := filepath.Clean(strings.TrimSpace(path))

	return os.Create(cleanPath)
}

func shouldExclude(line string, patterns []string) bool {
	for _, pattern := range patterns {
		if strings.Contains(line, pattern) {
			return true
		}
	}

	return false
}
