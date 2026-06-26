"""ndFWMig — entry point."""

import sys
import os

# Allow running directly from the project root
sys.path.insert(0, os.path.dirname(__file__))

from fwmig.gui.app import FWMigApp


def main() -> None:
    app = FWMigApp()
    app.mainloop()


if __name__ == "__main__":
    main()
