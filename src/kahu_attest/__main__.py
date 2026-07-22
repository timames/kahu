"""Allow running verify CLI as: python -m kahu_attest"""

from kahu_attest.verify import main
import sys

sys.exit(main())
