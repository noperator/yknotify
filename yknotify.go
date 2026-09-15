package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const defaultPredicate = `(processImagePath == "/kernel" AND senderImagePath ENDSWITH "IOHIDFamily") OR (subsystem CONTAINS "CryptoTokenKit")`

// yubicoVendorID is Yubico's USB vendor ID.
const yubicoVendorID = "0x1050"

var (
	predicate = flag.String("predicate", defaultPredicate, "NSPredicate filter for log stream")
	noFilter  = flag.Bool("no-filter", false, "Disable log filtering (warning: high CPU usage)")
	vendors   = flag.String("vendor", yubicoVendorID, "Comma-separated USB vendor IDs (hex) whose HID devices can signal a touch")
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

var (
	ioregDeviceRe = regexp.MustCompile(`\+-o AppleUserUSBHostHIDDevice\s+<class [^,]+, id (0x[0-9a-fA-F]+)`)
	ioregVendorRe = regexp.MustCompile(`"VendorID" = (\d+)`)
)

// hidVendors resolves the IORegistry entry ID of a USB HID device to the USB
// vendor ID of the device behind it. The kernel logs HID opens by registry
// entry ID only, so the IORegistry is what lets us tell a YubiKey apart from
// any other USB HID device that gets opened through IOHIDLibUserClient.
type hidVendors struct {
	byDevice    map[string]uint64 // registry entry ID -> USB vendor ID
	allowed     map[uint64]bool   // USB vendor IDs that may signal a touch
	lastRefresh time.Time
}

func newHIDVendors(vendorList string) (*hidVendors, error) {
	allowed, err := parseVendorIDs(vendorList)
	if err != nil {
		return nil, err
	}
	h := &hidVendors{byDevice: map[string]uint64{}, allowed: allowed}
	h.refresh()
	return h, nil
}

func parseVendorIDs(s string) (map[uint64]bool, error) {
	allowed := map[uint64]bool{}
	for _, field := range strings.Split(s, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		v, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(field), "0x"), 16, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid USB vendor ID %q: %w", field, err)
		}
		allowed[v] = true
	}
	if len(allowed) == 0 {
		return nil, fmt.Errorf("no USB vendor IDs given")
	}
	return allowed, nil
}

// refresh snapshots the vendor ID of every attached USB HID device.
func (h *hidVendors) refresh() error {
	h.lastRefresh = time.Now()
	out, err := exec.Command("ioreg", "-c", "AppleUserUSBHostHIDDevice", "-r", "-l", "-w", "0").Output()
	if err != nil {
		return err
	}

	byDevice := map[string]uint64{}
	var device string
	scanner := bufio.NewScanner(bytes.NewReader(out))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()

		// A new node ends the previous device's own properties; nested child
		// nodes (e.g. IOHIDLibUserClient) carry vendor IDs we must not credit
		// to the parent.
		if strings.Contains(line, "+-o ") {
			device = ""
			if m := ioregDeviceRe.FindStringSubmatch(line); m != nil {
				device = normalizeRegistryID(m[1])
			}
			continue
		}
		if device == "" {
			continue
		}
		if _, seen := byDevice[device]; seen {
			continue
		}
		if m := ioregVendorRe.FindStringSubmatch(line); m != nil {
			if v, err := strconv.ParseUint(m[1], 10, 64); err == nil {
				byDevice[device] = v
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	h.byDevice = byDevice
	return nil
}

// allows reports whether the HID device with the given IORegistry entry ID
// belongs to a vendor that may signal a touch. An unresolvable device is
// allowed, so that an unexpected IORegistry layout can still only cost us a
// false positive — never a missed touch prompt.
func (h *hidVendors) allows(deviceID string) bool {
	id := normalizeRegistryID(deviceID)
	if v, ok := h.byDevice[id]; ok {
		return h.allowed[v]
	}
	// Device attached since the last snapshot. Re-read, but not on every
	// unknown device in a burst.
	if time.Since(h.lastRefresh) < time.Second {
		return true
	}
	if err := h.refresh(); err != nil {
		return true
	}
	v, ok := h.byDevice[id]
	if !ok {
		return true
	}
	return h.allowed[v]
}

func normalizeRegistryID(s string) string {
	s = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "0x")
	s = strings.TrimLeft(s, "0")
	if s == "" {
		return "0"
	}
	return s
}

func streamLogs() error {
	hid, err := newHIDVendors(*vendors)
	if err != nil {
		return err
	}

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
			// AppleUserUSBHostHIDDevice alone is not enough either: any USB HID
			// device is opened this way, so check the vendor behind the device.
			if strings.Contains(msg, "AppleUserUSBHostHIDDevice:") && strings.Contains(msg, "open by IOHIDLibUserClient:") {
				parts := strings.Split(msg, " open by ")
				if len(parts) == 2 {
					clientID := strings.Split(parts[1], " ")[0]
					deviceID := parts[0][strings.LastIndex(parts[0], ":")+1:]
					yubiKeyClients[clientID] = hid.allows(deviceID)
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
