#!/bin/bash

# Adjust as needed
YKNTFY_BIN="Users/<USER>/go/bin/yknotify"

# brew install terminal-notifier
TERM_NTFY_BIN="/opt/homebrew/bin/terminal-notifier"

# Stream yknotify output and process each line
"$YKNTFY_BIN" | while IFS= read -r line; do

    message=$(echo "$line" | jq -r '.type')

    # Send notification using terminal-notifier
    if [[ -x "$TERM_NTFY_BIN" ]]; then
        # List of sounds: https://apple.stackexchange.com/a/479714
        # Use "legacy name" as noted here: https://github.com/julienXX/terminal-notifier/issues/283#issuecomment-832569237
        "$TERM_NTFY_BIN" -title "yknotify" -message "$message" -sound Submarine
    else
        # Fallback to AppleScript if terminal-notifier is not installed
        osascript -e "display notification \"$message\" with title \"yknotify\""
    fi
done
