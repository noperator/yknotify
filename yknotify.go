package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

const defaultPredicate = `(processImagePath == "/kernel" AND senderImagePath ENDSWITH "IOHIDFamily") OR (subsystem CONTAINS "CryptoTokenKit")`

var (
	predicate = flag.String("predicate", defaultPredicate, "NSPredicate filter for log stream")
	noFilter  = flag.Bool("no-filter", false, "Disable log filtering (warning: high CPU usage)")
)

var (
	reIoregID     = regexp.MustCompile(`id (0x[0-9a-fA-F]+)`)
	reIoregVendor = regexp.MustCompile(`"VendorID"\s*=\s*(0x[0-9a-fA-F]+)`)
)

// deviceIsYubico is package-level (rather than local to streamLogs, like
// clientIsYubico) because it's written by the runYubicoPoller goroutine
// and read by the log-processing loop in streamLogs — both need to reach
// the same map, guarded by deviceIsYubicoMu.
var (
	deviceIsYubicoMu sync.RWMutex
	deviceIsYubico   = make(map[string]bool)
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

// pollYubicoDevices runs `ioreg -k VendorID -l -w0 -x` and returns a fresh
// map of registry IDs -> true for every USB device whose VendorID is Yubico's
// (0x1050). Sample ioreg output for one matching object looks like:
//
//	+-o AppleUserUSBHostHIDDevice  <class AppleUserHIDDevice, id 0x100000d8a, ...>
//	    {
//	      ...
//	      "VendorID" = 0x1050
//	      ...
//	    }
//
// Parsing relies on ioreg's tree format: each object's header line (containing
// its "id 0x...") is followed by that same object's indented property block,
// before the next object's header line appears. So we track the most recently
// seen header's ID, and if a "VendorID" = 0x1050 line follows before the next
// header, we record that ID as Yubico's.
func pollYubicoDevices() (map[string]bool, error) {
	out, err := exec.Command("ioreg", "-k", "VendorID", "-l", "-w0", "-x").Output()
	if err != nil {
		return nil, err
	}

	result := make(map[string]bool)
	var currentID string
	for _, line := range strings.Split(string(out), "\n") {
		if m := reIoregID.FindStringSubmatch(line); m != nil {
			currentID = m[1]
		}
		if m := reIoregVendor.FindStringSubmatch(line); m != nil && m[1] == "0x1050" {
			result[currentID] = true
		}
	}
	return result, nil
}

func runYubicoPoller() {
	interval := 5 * time.Second
	for {
		devices, err := pollYubicoDevices()
		if err == nil {
			deviceIsYubicoMu.Lock()
			deviceIsYubico = devices
			deviceIsYubicoMu.Unlock()
			if len(devices) > 0 {
				interval = 60 * time.Second
			} else {
				interval = 5 * time.Second
			}
		}
		time.Sleep(interval)
	}
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

	go runYubicoPoller()

	state := &TouchState{}
	scanner := bufio.NewScanner(stdout)
	// clientIsYubico maps a client's address -> whether it was opened on a Yubico device.
	clientIsYubico := make(map[string]bool)

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
			if strings.Contains(msg, "AppleUserUSBHostHIDDevice:") && strings.Contains(msg, "open by IOHIDLibUserClient:") {
				parts := strings.Split(msg, " open by ")
				if len(parts) == 2 {
					devParts := strings.SplitN(parts[0], ":", 2)
					clientAddr := strings.Split(parts[1], " ")[0]
					if len(devParts) == 2 {
						deviceIsYubicoMu.RLock()
						isYubico := deviceIsYubico[devParts[1]]
						deviceIsYubicoMu.RUnlock()
						clientIsYubico[clientAddr] = isYubico
					}
				}
			}

			// e.g., AppleUserUSBHostHIDDevice:0x100000c81 close by IOHIDLibUserClient:0x10016f869 (0x1)
			if strings.Contains(msg, "AppleUserUSBHostHIDDevice:") && strings.Contains(msg, "close by IOHIDLibUserClient:") {
				parts := strings.Split(msg, " close by ")
				if len(parts) == 2 {
					clientAddr := strings.Split(parts[1], " ")[0]
					delete(clientIsYubico, clientAddr)
				}
			}

			// e.g., IOHIDLibUserClient:0x10016f869 startQueue
			if strings.HasSuffix(msg, "startQueue") {
				clientAddr := strings.Split(msg, " ")[0]
				state.fido2Needed = clientIsYubico[clientAddr]
			} else if strings.HasSuffix(msg, "stopQueue") {
				clientAddr := strings.Split(msg, " ")[0]
				if clientIsYubico[clientAddr] {
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
