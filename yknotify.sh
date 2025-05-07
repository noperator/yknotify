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
        "$TERM_NTFY_BIN" -title "yknotify" -message "$message"
    else
        # Fallback to AppleScript if terminal-notifier is not installed
        osascript -e "display notification \"$message\" with title \"yknotify\""
    fi
done
