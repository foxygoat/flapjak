package main

import (
	"fmt"
	"log/slog"
	"os"
)

type LogFlags struct {
	Level  string `default:"info" enum:"debug,info,warn,error" help:"Log messages of level and higher (${enum})"`
	Format string `default:"default" enum:"default,json,text" help:"Log output format (${enum})"`
}

var levels = map[string]slog.Level{
	"debug": slog.LevelDebug,
	"info":  slog.LevelInfo,
	"warn":  slog.LevelWarn,
	"error": slog.LevelError,
}

func (l *LogFlags) AfterApply() error {
	level, ok := levels[l.Level]
	if !ok {
		return fmt.Errorf("unknown log level: %s", l.Level)
	}
	options := slog.HandlerOptions{Level: level}

	var logger *slog.Logger
	switch l.Format {
	case "default":
		slog.SetLogLoggerLevel(level)
		logger = slog.Default()
	case "text":
		logger = slog.New(slog.NewTextHandler(os.Stderr, &options))
	case "json":
		logger = slog.New(slog.NewJSONHandler(os.Stderr, &options))
	default:
		return fmt.Errorf("unknown log format: %s", l.Format)
	}

	slog.SetDefault(logger)

	return nil
}
