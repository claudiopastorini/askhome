import uuid

from datetime import datetime

from .exceptions import InvalidValueException
from .utils import get_interface_string


def create_interface(data, context=None):
    """Create a specific ``Interface`` subclass according to the interface type.

    Each ``Interface`` subclass has specific properties to access interface data more easily and differing ``response`` arguments for direct response creation.
    """

    directive = data['directive']

    header = directive['header']

    namespace = header['namespace']
    directive_name = header['name']

    # Return Interface subtype for specific interfaces
    if namespace == 'Alexa.Authorization':
        if directive_name == 'AcceptGrant':
            return AcceptGrantInterface(data, context)

    if namespace == 'Alexa.Discovery':
        if directive_name == 'Discover':
            return DiscoverInterface(data, context)

    if namespace == 'Alexa':
        if directive_name == 'ReportState':
            return StateReportInterface(data, context)

    if namespace == 'Alexa.PowerController':
        if directive_name == 'TurnOn' or directive_name == 'TurnOff':
            return PowerControllerInterface(data, context)

    if namespace == 'Alexa.PercentageController':
        if directive_name == 'SetPercentage' or directive_name == 'AdjustPercentage':
            return PercentageControllerInterface(data, context)

    if namespace == 'Alexa.PowerLevelController':
        if directive_name == 'SetPowerLevel' or directive_name == 'AdjustPowerLevel':
            return PowerLevelControllerInterface(data, context)

    if namespace == 'Alexa.RangeController':
        if directive_name == 'SetRangeValue' or directive_name == 'AdjustRangeValue':
            return RangeControllerInterface(data, context)

    return Interface(data, context)


class Interface(object):
    """Base Interface class for parsing Alexa interface data.

    Attributes:
        data (dict): Raw event data from the lambda handler.
        context (object): Context object from the lambda handler.
        header (dict): Header of the Alexa interface.
        payload (dict): Payload of the Alexa interface.
        name (str): Interface name from the ``name`` field in header.
        access_token (str): OAuth token from the ``accessToken`` field in payload.
        custom_data (Any): Attribute for saving custom data through
            ``Smarthome.prepare_handler``

    Attributes:
        context (TYPE): Description
        custom_data (dict): Description
        data (TYPE): Description
        directive_name (TYPE): Description
        endpoint (TYPE): Description
        endpoint_id (TYPE): Description
        header (TYPE): Description
        payload (TYPE): Description
        token (TYPE): Description
    """

    def __init__(self, data, context=None):
        self.data = data
        self.context = context

        directive = data['directive']

        self.header = directive['header']
        self.directive_name = self.header['name']
        self.endpoint = directive.get('endpoint')
        self.payload = directive.get('payload')

        self.custom_data = {}

        self.endpoint_id = None if self.endpoint is None else self.endpoint['endpointId']

        if self.endpoint_id is not None:
            self.token = self.endpoint.get('scope', {}).get('token', None)

    def response_header(self, namespace=None, name=None):
        """Generate response header with copied values from the interface and correct name."""

        # Copy interface header and just change the name
        header = dict(self.header)

        if namespace is not None:
            header['namespace'] = namespace
        else:
            header['namespace'] = self.header['namespace']

        if name is not None:
            header['name'] = name
        else:
            header['name'] = f"{self.directive_name}.Response"

        header['messageId'] = str(uuid.uuid4())

        return header

    def raw_response(self, header=None, endpoint=None, payload=None):
        """Compose response from raw payload and header dicts"""

        if header is None:
            header = self.response_header()

        if payload is None:
            payload = {}

        response = {'event': {'header': header, 'payload': payload}}
        if endpoint is not None:
            response['endpoint'] = endpoint
        elif self.endpoint is not None:
            response['endpoint'] = self.endpoint

        return response

    def response(self, *args, **kwargs):
        """Return response with empty payload. Arguments and implementation of this method differ in
        each Interface subclass.
        """
        return self.raw_response()

    def exception_response(self, exception):
        """Create response from exception instance."""

        header = self.response_header(namespace="Alexa", name="ErrorResponse")

        if not hasattr(exception, 'payload'):
            payload = {
                "type": exception.type,
                "message": exception.message
            }
        else:
            payload = exception.payload

        return self.raw_response(header=header, payload=payload)


class InterfaceWithState(Interface):

    def __init__(self, data, context=None):
        super().__init__(data, context)

        self.cookie = self.endpoint.get('cookie')

    @classmethod
    def create_property_response(cls, name, value, time_of_sample=None, uncertainty_in_milliseconds=0, namespace=None):

        if time_of_sample is None:
            time_of_sample = datetime.utcnow()

        if namespace is None:
            namespace = get_interface_string(cls.__name__)

        property_response = {
            "namespace": namespace,
            "name": name,
            "value": value,
            "timeOfSample": time_of_sample.strftime('%Y-%m-%dT%H:%M:%SZ'),
            "uncertaintyInMilliseconds": uncertainty_in_milliseconds
        }

        return property_response


class ControllerInterface(InterfaceWithState):

    def response(self):
        header = self.response_header(namespace="Alexa", name="Response")

        endpoint = self.endpoint
        if 'cookie' in endpoint.keys():
            del endpoint['cookie']

        response = self.raw_response(header=header, endpoint=endpoint)

        response['context'] = {}

        return response


class AcceptGrantInterface(Interface):
    """Interface class for Alexa AcceptGrant interface."""

    def __init__(self, data, context=None):

        super().__init__(data, context)

        self.token = self.payload['grantee']['token']


class DiscoverInterface(Interface):
    """Interface class for Alexa DiscoverAppliancesInterface."""

    def __init__(self, data, context=None):

        super().__init__(data, context)

        self.token = self.payload.get('scope', {}).get('token', None)

    def response(self, smarthome):
        """Generate DiscoverAppliancesResponse from endpoints added to the passed ``Smarthome``.

        Details of each endpoint are resolved in order of priority:
        ``Smarthome.add_endpoint`` kwargs -> ``Appliance.Details`` -> ``Smarthome.__init__`` kwargs
        """
        discovered = []
        for appl, details in smarthome.endpoints.values():
            discovered.append(details)

        return self.raw_response(payload={'endpoints': discovered})


class StateReportInterface(InterfaceWithState):
    """Interface class for Alexa DiscoverAppliancesInterface."""

    def response(self, property_responses):
        """Generate DiscoverAppliancesResponse from endpoints added to the passed ``Smarthome``.

        Details of each endpoint are resolved in order of priority:
        ``Smarthome.add_endpoint`` kwargs -> ``Appliance.Details`` -> ``Smarthome.__init__`` kwargs
        """
        header = self.response_header(namespace="Alexa", name="StateReport")

        endpoint = self.endpoint
        if 'cookie' in endpoint.keys():
            del endpoint['cookie']

        response = self.raw_response(header=header, endpoint=endpoint)

        response['context'] = {
            'properties': property_responses
        }

        return response


class EndpointHealthInterface(ControllerInterface):
    """Interface class for Alexa.PowerController Interface"""

    def response(self, connectivity=None, time_of_sample=None, uncertainty_in_milliseconds=0):
        response = super().response()

        if connectivity is None:
            connectivity = "OK"

        response['context']['properties'] = []

        connectivity_state_property = self.create_property_response("connectivity", connectivity, time_of_sample, uncertainty_in_milliseconds)

        response['context']['properties'].append(connectivity_state_property)

        return response


class PowerControllerInterface(ControllerInterface):
    """Interface class for Alexa.PowerController Interface"""

    @property
    def power_state(self):
        if self.directive_name == "TurnOn":
            power_state = True
        elif self.directive_name == "TurnOff":
            power_state = False
        else:
            raise InvalidValueException()

        return power_state

    def response(self, power_state=None, time_of_sample=None, uncertainty_in_milliseconds=0):
        response = super().response()

        if power_state is None:
            power_state = "ON" if self.power_state else "OFF"

        response['context']['properties'] = []

        power_state_property = self.create_property_response("powerState", power_state, time_of_sample, uncertainty_in_milliseconds)

        response['context']['properties'].append(power_state_property)

        return response


class BrigthnessControllerInterface(ControllerInterface):
    """Interface class for Alexa.BrightnessController Interface"""

    @property
    def brightness(self):
        return self.payload.get('brightness')

    @property
    def brightness_delta(self):
        return self.payload.get('brightnessDelta')

    def response(self, brightness, time_of_sample=None, uncertainty_in_milliseconds=0):
        response = super().response()

        response['context']['properties'] = []

        brightness_property = self.create_property_response("brightness", brightness, time_of_sample, uncertainty_in_milliseconds)

        response['context']['properties'].append(brightness_property)

        return response


class PercentageControllerInterface(ControllerInterface):
    """Interface class for Alexa.PercentageController Interface"""

    @property
    def percentage(self):
        return self.payload.get('percentage')

    @property
    def percentage_delta(self):
        return self.payload.get('percentageDelta')

    def response(self, percentage, time_of_sample=None, uncertainty_in_milliseconds=0):
        response = super().response()

        response['context']['properties'] = []

        percentage_state_property = self.create_property_response("percentage", percentage, time_of_sample, uncertainty_in_milliseconds)

        response['context']['properties'].append(percentage_state_property)

        return response


class PowerLevelControllerInterface(ControllerInterface):
    """Interface class for Alexa.PowerLevelController Interface"""

    @property
    def power_level(self):
        return self.payload.get('powerLevel')

    @property
    def powerLevelDelta(self):
        return self.payload.get('powerLevelDelta')

    def response(self, power_level, time_of_sample=None, uncertainty_in_milliseconds=0):
        response = super().response()

        response['context']['properties'] = []

        power_level_state_property = self.create_property_response("powerLevel", power_level, time_of_sample, uncertainty_in_milliseconds)

        response['context']['properties'].append(power_level_state_property)

        return response


class RangeControllerInterface(ControllerInterface):
    """Interface class for Alexa.RangeController Interface"""

    @property
    def range_value(self):
        return self.payload.get('rangeValue')

    @property
    def range_value_delta(self):
        return self.payload.get('rangeValueDelta')

    def response(self, range_value, time_of_sample=None, uncertainty_in_milliseconds=0):
        response = super().response()

        response['context']['properties'] = []

        range_value_state_property = self.create_property_response("rangeValue", range_value, time_of_sample, uncertainty_in_milliseconds)

        response['context']['properties'].append(range_value_state_property)

        return response
