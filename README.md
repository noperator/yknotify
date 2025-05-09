<div align="center">
  <kbd>
    <img src="notification.png" width="500px"/>
  </kbd>
</div>
<br/>

`yknotify` watches macOS logs (via `log stream` CLI command) for events that I've determined, through trial and error, are heuristically associated with the YubiKey waiting for touch. I primarily use the FIDO2 and OpenPGP features and haven't tested other applications listed in `ykman info` (e.g., Yubico OTP, FIDO U2F, OATH, PIV, YubiHSM Auth).

When waiting for FIDO2 touch, we'll see this message logged once (with example hex value):

```
kernel: (IOHIDFamily) IOHIDLibUserClient:0x123456789 startQueue
```

When waiting for OpenPGP touch, we'll see this message logged repeatedly:

```
usbsmartcardreaderd: [com.apple.CryptoTokenKit:ccid] Time extension received
```

As soon as the YubiKey is touched, we'll get a new/different log message in the same category. So the strategy here is to check if either of the above messages are the last one logged in their respective categories, and if so, notify the user to touch the YubiKey.

### Install

```
go install github.com/noperator/yknotify@latest
```

### Usage

Run from CLI.

```
yknotify
{"ts":"2025-02-12T20:09:03Z","type":"FIDO2"}
{"ts":"2025-02-12T20:09:14Z","type":"OpenPGP"}
```

Run as LaunchAgent logging to Notification Center.

```
git clone https://github.com/noperator/yknotify
cd yknotify

# Enable terminal-based Notification Center messages
brew install terminal-notifier

# Install agent files
sed -i .bu -E "s/<USER>/$USER/g" yknotify.sh com.user.yknotify.plist
cp yknotify.sh "$HOME/"
cp com.user.yknotify.plist "$HOME/Library/LaunchAgents/"

# Load + start service
launchctl load "$HOME/Library/LaunchAgents/com.user.yknotify.plist"
launchctl start com.user.yknotify
```

### Troubleshooting

I've seen a few rare false positives (i.e., a log when the YubiKey is not waiting for touch) that I haven't diagnosed—but _no_ false negatives (i.e., no log when the YubiKey is waiting for touch). If you see false anythings, please open an issue with the log message and I'll try to add a filter for it.

### See also

- https://github.com/maximbaz/yubikey-touch-detector/issues/5#issuecomment-2568300068
- https://news.ycombinator.com/item?id=43029385

### To-do

- [ ] perhaps add a debug flag to show context around related log messages
- [x] add LaunchAgent example
- [x] show how to notify with osascript
