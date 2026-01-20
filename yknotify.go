package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

const defaultPredicate = `(processImagePath == "/kernel" AND senderImagePath ENDSWITH "IOHIDFamily") OR (subsystem CONTAINS "CryptoTokenKit")`

var (
	predicate = flag.String("predicate", defaultPredicate, "NSPredicate filter for log stream")
	noFilter  = flag.Bool("no-filter", false, "Disable log filtering (warning: high CPU usage)")
	once      = flag.Bool("once", false, "Exit after emitting one event")
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
			if *once {
				os.Exit(0)
			}
		}
	}
	if ts.openPGPNeeded {
		event := TouchEvent{
			Type:      "OpenPGP",
			Timestamp: now.UTC().Format(time.RFC3339),
		}
		if bytes, err := json.Marshal(event); err == nil {
			fmt.Println(string(bytes))
			if *once {
				os.Exit(0)
			}
		}
	}
	ts.lastNotify = now
}

func streamLogs() error {
	args := []string{"stream", "--level", "debug", "--style", "ndjson"}
	if !*noFilter {
		args = append(args, "--predicate", *predicate)
	}
	cmd := exec.Command("log", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	state := &TouchState{}
	scanner := bufio.NewScanner(stdout)
	yubiKeyClients := make(map[string]bool)

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
			msg := entry.EventMessage

			// e.g., AppleUserUSBHostHIDDevice:0x100000c81 open by IOHIDLibUserClient:0x10016f869 (0x1)
			// Other HID types (e.g., AppleUSBTopCaseHIDDriver) do not correspond to YubiKey and will trigger a false positive.
			if strings.Contains(msg, "AppleUserUSBHostHIDDevice:") && strings.Contains(msg, "open by IOHIDLibUserClient:") {
				parts := strings.Split(msg, " open by ")
				if len(parts) == 2 {
					clientID := strings.Split(parts[1], " ")[0]
					yubiKeyClients[clientID] = true
				}
			}

			// e.g., IOHIDLibUserClient:0x10016f869 startQueue
			// Only trigger FIDO2 for tracked YubiKey clients.
			if strings.HasSuffix(msg, "startQueue") {
				clientID := strings.Split(msg, " ")[0]
				state.fido2Needed = yubiKeyClients[clientID]
			} else if strings.HasSuffix(msg, "stopQueue") {
				clientID := strings.Split(msg, " ")[0]
				if yubiKeyClients[clientID] {
					state.fido2Needed = false
				}
			}

		case strings.HasSuffix(entry.ProcessImagePath, "usbsmartcardreaderd") &&
			strings.HasSuffix(entry.Subsystem, "CryptoTokenKit"):
			state.openPGPNeeded = entry.EventMessage == "Time extension received"
		}
		state.checkAndNotify()
	}

	return scanner.Err()
}

func main() {
	flag.Parse()
	log.SetFlags(0)
	if err := streamLogs(); err != nil {
		log.Fatal(err)
	}
}
