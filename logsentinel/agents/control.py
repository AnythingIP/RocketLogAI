"""
Multi-platform remote control — voice/text natural language to Windows/Mac.
"""

from __future__ import annotations

import re
from typing import Any


class RemoteControl:
    """Parse natural language into platform-specific control commands."""

    PLATFORM_COMMANDS = {
        "windows": {
            "open_app": "Start-Process '{app}'",
            "browse": "Start-Process 'msedge' '{url}'",
            "lock": "rundll32.exe user32.dll,LockWorkStation",
        },
        "macos": {
            "open_app": "open -a '{app}'",
            "browse": "open '{url}'",
            "lock": "/System/Library/CoreServices/Menu\\ Extras/User.menu/Contents/Resources/CGSession -suspend",
        },
        "linux": {
            "open_app": "xdg-open '{app}'",
            "browse": "xdg-open '{url}'",
            "lock": "loginctl lock-session",
        },
    }

    def parse_intent(self, text: str) -> dict[str, Any]:
        text_lower = text.lower().strip()

        if m := re.search(r"open\s+(.+?)(?:\s+on\s+|$)", text_lower):
            return {"action": "open_app", "app": m.group(1).strip(), "raw": text}

        if m := re.search(r"(?:browse|go to|visit)\s+(https?://\S+|\S+\.\S+)", text_lower):
            url = m.group(1)
            if not url.startswith("http"):
                url = f"https://{url}"
            return {"action": "browse", "url": url, "raw": text}

        if any(w in text_lower for w in ("lock screen", "lock the", "lock computer")):
            return {"action": "lock", "raw": text}

        if any(w in text_lower for w in ("screenshot", "screen shot")):
            return {"action": "screenshot", "raw": text}

        return {"action": "unknown", "raw": text}

    def to_command(self, intent: dict[str, Any], platform: str = "windows") -> str:
        platform = platform.lower()
        if platform == "darwin":
            platform = "macos"
        cmds = self.PLATFORM_COMMANDS.get(platform, self.PLATFORM_COMMANDS["linux"])
        action = intent.get("action", "unknown")

        if action == "open_app":
            return cmds["open_app"].format(app=intent.get("app", ""))
        if action == "browse":
            return cmds["browse"].format(url=intent.get("url", ""))
        if action == "lock":
            return cmds["lock"]
        if action == "screenshot":
            if platform == "windows":
                return "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.SendKeys]::SendWait('%{PRTSC}')"
            if platform == "macos":
                return "screencapture -x ~/Desktop/screenshot.png"
            return "import -window root ~/screenshot.png"

        return f"# Unrecognized command: {intent.get('raw', '')}"