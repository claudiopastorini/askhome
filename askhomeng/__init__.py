import logging

# Initialize logger that is used in other modules
logger = logging.getLogger('askhomeng')

from .endpoint import Categories
from .endpoint import Endpoint
from .interfaces import create_interface
from .smarthome import Smarthome

