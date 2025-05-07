package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"
)

type LogEntry struct {
	ProcessImagePath string `json:"processImagePath"`
	SenderImagePath  string `json:"senderImagePath"`
	Subsystem        string `json:"subsystem"`
	EventMessage     string `json:"eventMessage"`
}

type TouchState struct {
	fido2Needed   bool
	openPGPNeeded bool
	lastNotify    time.Time
}

type TouchEvent struct {
	Timestamp string `json:"ts"`
	Type      string `json:"type"`
}

func (ts *TouchState) checkAndNotify() {
	now := time.Now()
	if now.Sub(ts.lastNotify) < time.Second {
		return
	}

	if ts.fido2Needed {
		event := TouchEvent{
			Type:      "FIDO2",
			Timestamp: now.UTC().Format(time.RFC3339),
		}
		if bytes, err := json.Marshal(event); err == nil {
			fmt.Println(string(bytes))
		}
	}
	if ts.openPGPNeeded {
		event := TouchEvent{
			Type:      "OpenPGP",
			Timestamp: now.UTC().Format(time.RFC3339),
		}
		if bytes, err := json.Marshal(event); err == nil {
			fmt.Println(string(bytes))
		}
	}
	ts.lastNotify = now
}

func streamLogs() error {
	cmd := exec.Command("log", "stream", "--level", "debug", "--style", "ndjson")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	state := &TouchState{}
	scanner := bufio.NewScanner(stdout)

	go func() {
		ticker := time.NewTicker(time.Second)
		for range ticker.C {
			state.checkAndNotify()
		}
	}()

	for scanner.Scan() {
		var entry LogEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue
		}

		switch {
		case entry.ProcessImagePath == "/kernel" &&
			strings.HasSuffix(entry.SenderImagePath, "IOHIDFamily"):
			state.fido2Needed = strings.Contains(entry.EventMessage, "IOHIDLibUserClient:0x") &&
				strings.HasSuffix(entry.EventMessage, "startQueue")
		case strings.HasSuffix(entry.ProcessImagePath, "usbsmartcardreaderd") &&
			strings.HasSuffix(entry.Subsystem, "CryptoTokenKit"):
			state.openPGPNeeded = entry.EventMessage == "Time extension received"
		}
		state.checkAndNotify()
	}

	return scanner.Err()
}

func main() {
	log.SetFlags(0)
	if err := streamLogs(); err != nil {
		log.Fatal(err)
	}
}
