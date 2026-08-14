"""Allow running verify CLI as: python -m kahu_attest"""

import sys

from kahu_attest.verify import main

sys.exit(main())
