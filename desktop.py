#!/usr/bin/env python3
"""Entry point for the standalone desktop app (used by PyInstaller / double-click).

The real logic lives in backend/desktop.py; this stub exists because a script
inside a package can't be a PyInstaller entry point (relative imports).
"""

from backend.desktop import main

if __name__ == "__main__":
    main()
