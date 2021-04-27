from .utils import camel_to_snake


class AskhomeException(Exception):
    """Base askhome exception from which all inherit.

    These exceptions can be raised in ``Appliance`` actions or manually passed to
    ``Request.exception_response`` to create an error response.
    """

    def __init__(self, *args, **kwargs):
        """
        Args:
            name (str): Custom error name in header of generated response
            payload (dict): Custom payload of generated response
        """
        # If message was set in a subclass already, don't set it again
        if not hasattr(self, 'message'):
            self.message = self.__doc__
        if 'message' in kwargs:
            self.message = kwargs.pop('message')

        # Type of error response is equal to the UPPER_CASE of class name
        self.type = camel_to_snake(type(self).__name__).upper()

        super(AskhomeException, self).__init__(*args, **kwargs)

# Accept grant failed exception docstring is taken directly from:
# https://developer.amazon.com/en-US/docs/alexa/device-apis/alexa-authorization.html#acceptgrant-error-handling


class AcceptGrantFailedException(AskhomeException):
    """Failed to handle the AcceptGrant directive."""

# All following exception docstrings are taken directly from:
# https://developer.amazon.com/en-US/docs/alexa/device-apis/alexa-errorresponse.html


class AlreadyInOperationException(AskhomeException):
    """The operation can't be performed because the endpoint is already in operation."""


class BridgeUnreachableException(AskhomeException):
    """The bridge is unreachable or offline."""


class CloudControlDisabledException(AskhomeException):
    """The user can't control the device over the internet, and should control the device manually instead."""


class EndpointBusyException(AskhomeException):
    """The endpoint can't handle the directive because it is performing another action, which may or may not have originated from a request to Alexa."""


class EndpointLowPowerException(AskhomeException):
    """The endpoint can't handle the directive because the battery power is too low."""

    # TODO: percentageState


class EndpointUnreachableException(AskhomeException):
    """The endpoint is unreachable or offline."""


class ExpiredAuthorizationCredentialException(AskhomeException):
    """The authorization credential provided by Alexa has expired."""


class FirmwareOutOfDateException(AskhomeException):
    """The endpoint can't handle the directive because it's firmware is out of date."""


class HardwareMalfunctionException(AskhomeException):
    """The endpoint can't handle the directive because it has experienced a hardware malfunction."""


class InsufficientPermissionsException(AskhomeException):
    """Alexa does not have permissions to perform the specified action on the endpoint."""


class InternalErrorException(AskhomeException):
    """An error occurred that can't be described by one of the other error types."""


class InvalidAuthorizationCredentialException(AskhomeException):
    """The authorization credential provided by Alexa is invalid."""


class InvalidDirectiveException(AskhomeException):
    """The directive is not supported by the skill, or is malformed."""


class InvalidValueException(AskhomeException):
    """The directive contains a value that is not valid for the target endpoint. For example, an invalid heating mode, channel, or program value."""


class NoSuchEndpointException(AskhomeException):
    """The endpoint does not exist, or no longer exists."""


class NotCalibratedException(AskhomeException):
    """The endpoint can't handle the directive because it is in a calibration phase, such as warming up, or a user configuration is not set up yet on the device."""


class NotSupportedInCurrentModeException(AskhomeException):
    """The endpoint can't be set to the specified value because of its current mode of operation."""
    # TODO: currentDeviceMode


class NotInOperationException(AskhomeException):
    """The endpoint is not in operation."""


class PowerLevelNotSupportedException(AskhomeException):
    """The endpoint can't handle the directive because it doesn't support the requested power level."""


class RateLimitExceededException(AskhomeException):
    """The maximum rate at which an endpoint or bridge can process directives has been exceeded."""


class TemperatureValueOutOfRangeException(AskhomeException):
    """The endpoint can't be set to the specified value because it's outside the acceptable temperature range."""

    def __init__(self, minimum_value, maximum_value, scale, *args, **kwargs):
        super(TemperatureValueOutOfRangeException, self).__init__(*args, **kwargs)

        # TODO: use the scale enum
        self.scale = scale
        self.minimumValue = minimum_value
        self.maximumValue = maximum_value

        self.payload = {
            'type': self.type,
            'message': self.message,
            'validRange': {
                'minimumValue': {
                    'scale': self.scale,
                    'value': self.minimumValue
                },
                'maximumValue': {
                    'scale': self.scale,
                    'value': self.maximumValue
                }
            }
        }


class TooManyFailedAttemptsException(AskhomeException):
    """The number of allowed failed attempts, such as when entering a password, has been exceeded."""


class ValueOutOfRangeException(AskhomeException):
    """The endpoint can't be set to the specified value because it's outside the acceptable range."""

    def __init__(self, minimum_value, maximum_value, *args, **kwargs):
        super(ValueOutOfRangeException, self).__init__(*args, **kwargs)

        self.minimumValue = minimum_value
        self.maximumValue = maximum_value

        self.payload = {
            'type': self.type,
            'message': self.message,
            'validRange': {
                'minimumValue': self.minimumValue,
                'maximumValue': self.maximumValue
            }
        }
