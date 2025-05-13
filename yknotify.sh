#!/bin/bash

# List of sounds: https://apple.stackexchange.com/a/479714

# Adjust as needed
YKNTFY_BIN="/Users/<USER>/go/bin/yknotify"

# brew install terminal-notifier
TERM_NTFY_BIN="/opt/homebrew/bin/terminal-notifier"

# Stream yknotify output and process each line
LAST_NTFY=0
while IFS= read -r line; do

    # 2-second delay between notifications
    NOW="$(date +%s)"
    if [[ "$NOW" -le "$((LAST_NTFY + 2))" ]]; then
        continue
    fi
    LAST_NTFY="$NOW"

    # Send notification using terminal-notifier
    message="$(echo "$line" | jq -r '.type')"
    if [[ -x "$TERM_NTFY_BIN" ]]; then
        "$TERM_NTFY_BIN" -title "yknotify" -message "$message" -sound Submarine
    else
        # Fallback to AppleScript if terminal-notifier is not installed
        osascript -e "display notification \"$message\" with title \"yknotify\""
    fi

done < <("$YKNTFY_BIN")
