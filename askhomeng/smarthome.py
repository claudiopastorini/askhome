import json
import uuid

from oauthlib.oauth2.rfc6749.errors import InvalidGrantError
from requests.exceptions import HTTPError
from requests_oauthlib import OAuth2Session

from . import logger
from .endpoint import Categories
from .exceptions import AcceptGrantFailedException
from .exceptions import AskhomeException
from .exceptions import InternalErrorException
from .exceptions import InvalidDirectiveException
from .interfaces import ControllerInterface
from .interfaces import DiscoverInterface
from .interfaces import EndpointHealthInterface
from .interfaces import create_interface
from .utils import get_interface_string

# Uncomment for requests_oauthlib debug
# import logging
# import sys
# log = logging.getLogger('oauthlib')
# log.addHandler(logging.StreamHandler(sys.stdout))
# log.setLevel(logging.DEBUG)


class Smarthome(object):
    """Holds information about all endpoints and handles routing interfaces to endpoint interface.

    Attributes:
        endpoints (dict(str, (Endpoint, dict))): All registered endpoints with details dict.
        details (dict): Defaults for details of endpoints during DiscoverEndpointsInterface.

    """

    def __init__(self, **details):
        """
        Args:
            details (dict): Defaults for details of endpoints during DiscoverEndpointsInterface.
                See ``add_endpoint`` method for possible values.
        """
        self.endpoints = {}
        self.details = details

        self._discover_func = None
        self._get_endpoint_func = None
        self._report_state_func = None
        self._prepare_func = None
        self._retrieve_tokens_func = None
        self._store_tokens_func = None
        self._disconnect_user_func = None

    def add_endpoint(self, endpoint_id, endpoint_class,
                     manufacturer_name=None, description=None, friendly_name=None, display_categories=None, additional_attributes=None, connections=None, relationships=None, cookie=None,
                     model=None, manufacturer=None, serial_number=None, firmware_version=None, software_version=None, custom_identifier=None):
        """Register ``Endpoint`` so it can be discovered and routed to.

        The keyword arguments can be also defined in ``Smarthome.__init__`` and ``Details`` inner
        class in the endpoint. Resulting value is resolved in order of priority:
        ``Smarthome.add_endpoint`` kwargs -> ``Endpoint.Details`` -> ``Smarthome.__init__`` kwargs

        Args:
            endpoint_id (str): The identifier for the endpoint. The identifier must be unique across all devices for the skill. The identifier must be consistent for all discovery requests for the same device. An identifier can contain letters or numbers, spaces, and the following special characters: _ - = # ; : ? @ &. The identifier can't exceed 256 characters.
            endpoint_class (Endpoint): ``Endpoint`` subclass with marked interface.
            manufacturer_name (str): The name of the manufacturer of the device. This value can contain up to 128 characters.
            description (str): The description of the device. The description should contain the manufacturer name or how the device connects. For example, "Smart Lock by Sample Manufacturer" or "Wi-Fi Thermostat connected by SmartHub". This value can contain up to 128 characters.
            friendly_name (str): The name used by the user to identify the device. This value can contain up to 128 characters, and shouldn't contain special characters or punctuation. This field is required for all interfaces, with some exceptions. Check the documentation for your interface to see if this field is optional.
            display_categories (list): In the Alexa app, the category that your device is displayed in.
            additional_attributes (dict): Additional information about the endpoint. Amazon recommends that you include this field, because it can improve the user experience in the Alexa app.
            connections (list): Information about the methods that the device uses to connect to the internet and smart home hubs.
            relationships (dict): The endpoints that an endpoint is connected to. For example, a computer endpoint might be connected to a home network endpoint.
            cookie (dict): Information about the device that your skill uses. The contents of this property can't exceed 5000 bytes. The API doesn't read or use this data.
            manufacturer (str): The name of the manufacturer of the device. This value can contain up to 256 alphanumeric characters, and can contain punctuation.
            model (str): The name of the model of the device. This value can contain up to 256 alphanumeric characters, and can contain punctuation.
            serial_number (str): The serial number of the device. This value can contain up to 256 alphanumeric characters, and can contain punctuation.
            firmware_version (str): The firmware version of the device. This value can contain up to 256 alphanumeric characters, and can contain punctuation.
            software_version (str): The software version of the device. This value can contain up to 256 alphanumeric characters, and can contain punctuation.
            custom_identifier (str): Your custom identifier for the device. This identifier should be globally unique in your systems across different user accounts. This value can contain up to 256 alphanumeric characters, and can contain punctuation.
        """
        # The kwargs are explicitly named for better autocomplete

        # Helper function to get detail in hierarchy:
        # Smarthome.add_endpoint kwargs -> Endpoint.Details -> Smarthome.__init__ kwargs
        def get_detail(detail_name, arg, default=''):
            if arg is not None:
                return arg

            if hasattr(endpoint_class, 'Details') and hasattr(endpoint_class.Details, detail_name):
                return getattr(endpoint_class.Details, detail_name)

            return self.details.get(detail_name, default)

        # Creates the endpoint object
        details = {
            'endpointId': endpoint_id,
            'manufacturerName': get_detail('manufacturer_name', manufacturer_name, 'Unknown manufacturer'),
            'description': get_detail('description', description, 'No description'),
            'friendlyName': get_detail('friendly_name', friendly_name),
            'displayCategories': [category.name for category in get_detail('display_categories', display_categories, [Categories.OTHER])]
        }

        default_alexa_capability = {
            'type': "AlexaInterface",
            'interface': "Alexa",
            'version': "3"
        }

        # Creates the capability object for each of them
        for capability_name, capability in endpoint_class.capabilities.items():
            capability_object = {
                'type': "AlexaInterface",
                'interface': capability_name,
                'version': "3",
                'properties': {
                    'supported': [{'name': _property} for _property in capability['properties']],
                    'proactivelyReported': capability["proactively_reported"],
                    'retrievable': capability["retrievable"]
                }
            }
            capability_instance = capability['instance']
            if capability_instance is not None:
                capability_object['instance'] = capability_instance

            capability_resources = capability['capability_resources']
            if capability_resources is not None:
                capability_object['capabilityResources'] = capability_resources

            capability_configuration = capability['configuration']
            if capability_configuration is not None:
                capability_object['configuration'] = capability_configuration

            capability_semantics = capability['semantics']
            if capability_semantics is not None:
                capability_object['semantics'] = capability_semantics

            details.setdefault('capabilities', [default_alexa_capability]).append(capability_object)

        # Checks for not required additionalAttributes
        if get_detail('additional_attributes', additional_attributes, None) is not None:
            details['additionalAttributes'] = get_detail('additional_attributes', additional_attributes, None)

        # Checks for not required connections
        if get_detail('connections', connections, None) is not None:
            details['connections'] = get_detail('connections', connections, None)

        # Checks for not required relationships
        if get_detail('relationships', relationships, None) is not None:
            details['relationships'] = get_detail('relationships', relationships, None)

        # Checks for not required cookie
        if get_detail('cookie', cookie, None) is not None:
            details['cookie'] = get_detail('cookie', cookie, None)

        # Checks if additional attributes are set and overwrite the additionalAttributes object if present
        if get_detail('manufacturer', manufacturer, None) is not None:
            details.setdefault('additionalAttributes', {})['manufacturer'] = get_detail('manufacturer', manufacturer, None)
        if get_detail('model', model, None) is not None:
            details.setdefault('additionalAttributes', {})['model'] = get_detail('model', model, None)
        if get_detail('serial_number', serial_number, None) is not None:
            details.setdefault('additionalAttributes', {})['serialNumber'] = get_detail('serial_number', serial_number, None)
        if get_detail('firmware_version', firmware_version, None) is not None:
            details.setdefault('additionalAttributes', {})['firmwareVersion'] = get_detail('firmware_version', firmware_version, None)
        if get_detail('software_version', software_version, None) is not None:
            details.setdefault('additionalAttributes', {})['softwareVersion'] = get_detail('software_version', software_version, None)
        if get_detail('custom_identifier', custom_identifier, None) is not None:
            details.setdefault('additionalAttributes', {})['customIdentifier'] = get_detail('custom_identifier', custom_identifier, None)

        self.endpoints[endpoint_id] = (endpoint_class, details)

    def prepare_handler(self, func):
        """Decorator for a function that gets called before every interface.
        Useful to modify the interface processed, for instance add data to ``Interface.custom_data``
        """
        self._prepare_func = func
        return func

    def discover_handler(self, func):
        """Decorator for a function that handles the Alexa.Discovery interface instead of the ``Smarthome``.
        This can be useful for situations where querying the list of all devices is too expensive to be done every interface.
        Should be used in conjunction with the ``get_endpoint_handler`` decorator.
        """
        self._discover_func = func
        return func

    def get_endpoint_handler(self, func):
        """Decorator for a function that handles getting the ``Endpoint`` subclass instead of the ``Smarthome``.
        Should be used in conjunction with the ``discover_handler`` decorator.
        """
        self._get_endpoint_func = func
        return func

    def report_state_handler(self, func):
        """TODO
        """
        self._report_state_func = func
        return func

    def retrieve_tokens_handler(self, func):
        """TODO
        """
        self._retrieve_tokens_func = func
        return func

    def store_tokens_handler(self, func):
        """TODO
        """
        self._store_tokens_func = func
        return func

    def disconnect_user_handler(self, func):
        """TODO
        """
        self._disconnect_user_func = func
        return func

    def lambda_handler(self, event, context=None):
        """Main entry point for handling interfaces. Pass the AWS Lambda events here."""
        logger.debug(json.dumps(event, indent=2))

        response = self._lambda_handler(event, context)

        logger.debug(json.dumps(response, indent=2))

        return response

    def get_tokens(self, code: str):
        """Summary

        Args:
            code (str): Description

        Returns:
            TYPE: Description

        Raises:
            AcceptGrantFailedException: Description
        """
        logger.debug("Gettings OAuth2 tokens...")

        # Gets the Alexa credentials
        alexa_client_id = self.details.get('alexa_client_id', None)
        alexa_client_secret = self.details.get('alexa_client_secret', None)

        # Checks if client ID and client secret were provided
        if alexa_client_id is None or alexa_client_secret is None:
            raise AcceptGrantFailedException(message="Unable to call Login with Amazon to exchange the authorization code for access and refresh token because no client ID or client secret was provided.")

        # Creates the client
        session = OAuth2Session(client_id=alexa_client_id)
        # Fetches the token
        token = session.fetch_token('https://api.amazon.com/auth/o2/token',
                                    client_secret=alexa_client_secret,
                                    code=code)

        return token

    def remove_endpoint(self, endpoint_id: str, username: str):
        """See ``remove_endpoints()``.
        """
        self.remove_endpoints([endpoint_id], username)

    def remove_endpoints(self, endpoint_ids: list, username: str):
        """Summary

        Args:
            endpoint_ids (list): Description
            username (str): Description

        Raises:
            Exception: Description
            NotImplementedError: Description
            ValueError: Description
        """
        # Checks if the retrieve token function was provided
        if self._retrieve_tokens_func is None:
            raise NotImplementedError("No function provided for the retrieve of the user's tokens. Use @home.retrieve_tokens_handler decorator for provide a valid function")

        # Checks if the username was provided
        if username is None:
            raise ValueError("The username must be provided")

        # Obtains the users' tokens
        token = self._retrieve_tokens_func(username)

        headers = {"Authorization": f"Bearer {token['access_token']}"}
        payload = {
            "event": {
                "header": {
                    "namespace": "Alexa.Discovery",
                    "name": "DeleteReport",
                    "messageId": str(uuid.uuid4()),
                    "payloadVersion": "3"
                },
                "payload": {
                    "endpoints": [{"endpointId": endpoint_id} for endpoint_id in endpoint_ids],
                    "scope": {
                        "type": "BearerToken",
                        "token": token['access_token']
                    }
                }
            }
        }

        # Gets the Alexa credentials
        alexa_client_id = self.details.get('alexa_client_id', None)
        alexa_client_secret = self.details.get('alexa_client_secret', None)

        # Checks if client ID and client secret were provided
        if alexa_client_id is None or alexa_client_secret is None:
            raise Exception("Unable to rediscover because no client ID or client secret was provided.")

        # Creates the client with auto token refresh
        client = OAuth2Session(alexa_client_id,
                               token=token,
                               auto_refresh_url="https://api.amazon.com/auth/o2/token",
                               auto_refresh_kwargs={'client_id': alexa_client_id, 'client_secret': alexa_client_secret},
                               token_updater=lambda token: self._store_tokens_func(username, token))

        logger.debug(f"Sending: \n{json.dumps(payload, indent=2)}")

        # Makes the call
        try:
            response = client.post("https://api.eu.amazonalexa.com/v3/events",
                                   json=payload,
                                   headers=headers)
        except InvalidGrantError:
            logger.error("The authorization code is invalid, expired, revoked, or was issued to a different client_id. So the user is not more able to use the integration")

            # If the user provided a valid disconnection handler
            if self._disconnect_user_func is not None:
                # Calls it in order to allow the integration to clean the integration stuffs
                logger.debug("Calling the disconnect function...")
                self._disconnect_user_func(username)
            else:
                # Otherwise raise the exception and let the user decide what to do
                raise

        logger.debug(f"Response from Amazon Alexa: '{response}'")
        try:
            response.raise_for_status()
        except HTTPError as e:

            # If the error is Unauthorized error it means that the user is revoked the access to the Alexa skill
            if e.response.status_code == 401:
                logger.error("The user is not anymore authorized to use the integration")

                # If the user provided a valid disconnection handler
                if self._disconnect_user_func is not None:
                    # Calls it in order to allow the integration to clean the integration stuffs
                    logger.debug("Calling the disconnect function...")
                    self._disconnect_user_func(username)
                    return

            # Otherwise raise the exception
            raise

    def rediscover(self, username: str):
        """Summary

        Args:
            username (str): Description

        Raises:
            Exception: Description
            NotImplementedError: Description
            ValueError: Description
        """
        # Checks if the retrieve token function was provided
        if self._retrieve_tokens_func is None:
            raise NotImplementedError("No function provided for the retrieve of the user's tokens. Use @home.retrieve_tokens_handler decorator for provide a valid function")

        # Checks if the username was provided
        if username is None:
            raise ValueError("The username must be provided")

        # Obtains the users' tokens
        token = self._retrieve_tokens_func(username)

        # Creates a fake data dict in order to create a fake discovery event
        fake_discovery_data = {"directive": {"header": {"namespace": "Alexa.Discovery", "name": "Discover", "payloadVersion": "3", "messageId": "FAKE"}, "payload": {"scope": {"type": "BearerToken", "token": "FAKE"}}}}

        # Creates a discovery interface
        discovery_interface = DiscoverInterface(fake_discovery_data, None)

        # Adds the username to the fake interface
        discovery_interface.custom_data['username'] = username

        if self._discover_func is None:
            discovery_response = discovery_interface.response(self)
        else:
            discovery_response = self._discover_func(discovery_interface)

        # Obtains the users' tokens
        token = self._retrieve_tokens_func(username)

        payload = discovery_response

        # Adapts the discovery response to the AddOrUpdateReport event
        payload['event']['header']['name'] = "AddOrUpdateReport"
        payload['event']['header']['messageId'] = str(uuid.uuid4())
        payload['event']['payload']['scope'] = {'type': "BearerToken", 'token': token['access_token']}

        headers = {"Authorization": f"Bearer {token['access_token']}"}

        # Gets the Alexa credentials
        alexa_client_id = self.details.get('alexa_client_id', None)
        alexa_client_secret = self.details.get('alexa_client_secret', None)

        # Checks if client ID and client secret were provided
        if alexa_client_id is None or alexa_client_secret is None:
            raise Exception("Unable to rediscover because no client ID or client secret was provided.")

        # Creates the client with auto token refresh
        client = OAuth2Session(alexa_client_id,
                               token=token,
                               auto_refresh_url="https://api.amazon.com/auth/o2/token",
                               auto_refresh_kwargs={'client_secret': alexa_client_secret},
                               token_updater=lambda token: self._store_tokens_func(username, token))

        logger.debug(f"Sending: \n{json.dumps(payload, indent=2)}")

        # Makes the call
        try:
            response = client.post("https://api.eu.amazonalexa.com/v3/events",
                                   json=payload,
                                   headers=headers)
        except InvalidGrantError:
            logger.error("The authorization code is invalid, expired, revoked, or was issued to a different client_id. So the user is not more able to use the integration")

            # If the user provided a valid disconnection handler
            if self._disconnect_user_func is not None:
                # Calls it in order to allow the integration to clean the integration stuffs
                logger.debug("Calling the disconnect function...")
                self._disconnect_user_func(username)
            else:
                # Otherwise raise the exception and let the user decide what to do
                raise

        logger.debug(f"Response from Amazon Alexa: '{response}'")
        try:
            response.raise_for_status()
        except HTTPError as e:

            # If the error is Unauthorized error it means that the user is revoked the access to the Alexa skill
            if e.response.status_code == 401:
                logger.error("The user is not anymore authorized to use the integration")

                # If the user provided a valid disconnection handler
                if self._disconnect_user_func is not None:
                    # Calls it in order to allow the integration to clean the integration stuffs
                    logger.debug("Calling the disconnect function...")
                    self._disconnect_user_func(username)
                    return

            # Otherwise raise the exception
            raise

    def report_change(self, endpoint_id: str, username: str, changed_properties: list, not_changed_properties: list, interaction_type: str):
        """Summary

        Args:
            endpoint_id (str): Description
            username (str): Description
            changed_properties (list): Description
            not_changed_properties (list): Description
            interaction_type (str): Description

        Raises:
            Exception: Description
            NotImplementedError: Description
            ValueError: Description
        """
        # Checks if the retrieve token function was provided
        if self._retrieve_tokens_func is None:
            raise NotImplementedError("No function provided for the retrieve of the user's tokens. Use @home.retrieve_tokens_handler decorator for provide a valid function")

        # Checks if the username was provided
        if username is None:
            raise ValueError("The username must be provided")

        # Obtains the users' tokens
        token = self._retrieve_tokens_func(username)

        # Prepares the request
        headers = {"Authorization": f"Bearer {token['access_token']}"}
        payload = {
            "event": {
                "header": {
                    "namespace": "Alexa",
                    "name": "ChangeReport",
                    "messageId": str(uuid.uuid4()),
                    "payloadVersion": "3"
                },
                "endpoint": {
                    "scope": {
                        "type": "BearerToken",
                        "token": token['access_token']
                    },
                    "endpointId": endpoint_id,
                },
                "payload": {
                    "change": {
                        "cause": {
                            "type": interaction_type
                        },
                        "properties": changed_properties,
                    }
                }
            },
            "context": {
                "properties": not_changed_properties
            }
        }

        # Gets the Alexa credentials
        alexa_client_id = self.details.get('alexa_client_id', None)
        alexa_client_secret = self.details.get('alexa_client_secret', None)

        # Checks if client ID and client secret were provided
        if alexa_client_id is None or alexa_client_secret is None:
            raise Exception("Unable to remove endpoints because no client ID or client secret was provided.")

        # Creates the client with auto token refresh
        client = OAuth2Session(alexa_client_id,
                               token=token,
                               auto_refresh_url="https://api.amazon.com/auth/o2/token",
                               auto_refresh_kwargs={'client_id': alexa_client_id, 'client_secret': alexa_client_secret},
                               token_updater=lambda token: self._store_tokens_func(username, token))

        logger.debug(f"Sending: \n{json.dumps(payload, indent=2)}")

        # Makes the call
        try:
            response = client.post("https://api.eu.amazonalexa.com/v3/events",
                                   json=payload,
                                   headers=headers)
        except InvalidGrantError:
            logger.error("The authorization code is invalid, expired, revoked, or was issued to a different client_id. So the user is not more able to use the integration")

            # If the user provided a valid disconnection handler
            if self._disconnect_user_func is not None:
                # Calls it in order to allow the integration to clean the integration stuffs
                logger.debug("Calling the disconnect function...")
                self._disconnect_user_func(username)
            else:
                # Otherwise raise the exception and let the user decide what to do
                raise

        logger.debug(f"Response from Amazon Alexa: '{response}'")
        try:
            response.raise_for_status()
        except HTTPError as e:

            # If the error is Unauthorized error it means that the user is revoked the access to the Alexa skill
            if e.response.status_code == 401:
                logger.error("The user is not anymore authorized to use the integration")

                # If the user provided a valid disconnection handler
                if self._disconnect_user_func is not None:
                    # Calls it in order to allow the integration to clean the integration stuffs
                    logger.debug("Calling the disconnect function...")
                    self._disconnect_user_func(username)
                    return

            # Otherwise raise the exception
            raise

    def _lambda_handler(self, event, context=None):
        # This method is here just so it can be wrapped for logging

        # Fullfillment flow
        interface = create_interface(event, context)

        try:
            # Handle prepare interface
            if self._prepare_func is not None:
                logger.debug("Calling the prepare function...")
                self._prepare_func(interface)

            logger.debug(f"Received a '{interface.directive_name}' directive")

            # Handle Alexa.Authorization.AcceptGrant interface
            if interface.directive_name == 'AcceptGrant':

                # Calls the gets token function
                token = self.get_tokens(interface.payload['grant']['code'])

                # Checks if the store token function was provided
                if self._store_tokens_func is None:
                    logger.error("No function provided for the store of the user's tokens. Use @home.store_tokens_handler decorator for provide a valid function")
                    raise AcceptGrantFailedException(message="Unable to store the access and refresh tokens for the user because no function was provided.")

                # Stores the tokens for the user
                logger.debug("Calling the store token function...")
                self._store_tokens_func(interface.custom_data['username'], token)

                return interface.response()

            # Handle Alexa.Discovery.Discover interface
            if interface.directive_name == 'Discover':

                # Checks if a custom discovery function was provided
                if self._discover_func is None:
                    # If not manage internally
                    logger.debug("Use the internal discovery mechanism...")
                    return interface.response(self)

                # Uses the custom function
                logger.debug("Calling the custom discovery function...")
                return self._discover_func(interface)

            # Checks if a custom get endpoint function was provided
            if self._get_endpoint_func is None:
                # If not manage internally

                # Checks if the endpoint was added
                if interface.endpoint_id not in self.endpoints:
                    logger.error(f"Endpoint with ID: '{interface.endpoint_id}' not found among endpoints")
                    raise InvalidDirectiveException()

                logger.debug("Use the internal get endpoint mechanism...")
                endpoint_cls = self.endpoints[interface.endpoint_id][0]
            else:
                # Otherwise use the custom function
                logger.debug("Calling the custom get endpoint function...")
                endpoint_cls = self._get_endpoint_func(interface)

            # Handle ReportState interface
            if interface.directive_name == "ReportState":

                # Checks if the report state function was provided
                if self._report_state_func is None:
                    logger.error("No function provided for the report state. Use @home.report_state_handler decorator for provide a valid function")
                    raise InvalidDirectiveException()

                logger.debug("Calling the report state function...")
                return self._report_state_func(interface, endpoint_cls.properties['retrievable'].items())

            # If no endpoint was found
            if endpoint_cls is None:
                logger.error(f"No endpoint class was found for the endpoint with ID: '{interface.endpoint_id}'")
                raise InvalidDirectiveException()

            # Instantiates the endpoint with the just obtained class
            endpoint = endpoint_cls(interface)

            # Checks if the directive was supported by direct directive function
            if interface.directive_name in endpoint_cls.directive_handlers:
                logger.info(f"Using directive function for the directive: '{interface.directive_name}'...")

                # Calls the directive function
                response = endpoint_cls.directive_handlers[interface.directive_name](endpoint, interface)
            # or by interface
            elif get_interface_string(interface.__class__.__name__) in endpoint_cls.interface_handlers:
                logger.info(f"Using interface function for the directive: '{interface.directive_name}'...")

                # Checks if the directive is supported by the interface
                is_supported = False
                for capability_name, capability in endpoint_cls.capabilities.items():

                    if interface.directive_name in capability['supported_operations']:
                        is_supported = True
                        break

                if not is_supported:
                    logger.error(f"The interface '{get_interface_string(interface.__class__.__name__)}' does not support the directive: '{interface.directive_name}'. Adds the support with 'supported_operations' list or use the @Endpoint.interface_directive decorator")
                    raise InvalidDirectiveException()

                # Calls the interface function
                response = endpoint_cls.interface_handlers[get_interface_string(interface.__class__.__name__)](endpoint, interface)

            # otherwise raise exception
            else:
                raise InvalidDirectiveException()

            # If the user's implementation does not return any response
            if response is None:
                logger.debug(f"Creating default response for directive: '{interface.directive_name}'...")
                # Uses the default one
                response = interface.response()

            # Checks if it is needed to send also an endpoint health response
            if endpoint.needToSendEndpointHealth and isinstance(interface, ControllerInterface):
                logger.debug("Needs to manage also the 'Alexa.EndpointHealth' interface")
                # Creates an healt interface
                health_interface = EndpointHealthInterface(event, context)

                health_response = None
                if 'Alexa.EndpointHealth' in endpoint_cls.interface_handlers:
                    logger.info("Using interface function for the 'Alexa.EndpointHealth'...")
                    health_response = endpoint_cls.interface_handlers['Alexa.EndpointHealth'](endpoint, health_interface)

                # If the user did not provide the function or a valid response
                if health_response is None:
                    # Uses the default one
                    logger.debug("Creating default response for: 'Alexa.EndpointHealth'...")
                    health_response = health_interface.response()

                # Appends the endpoint health response
                response['context']['properties'].extend(health_response['context']['properties'])

            return response

        except AskhomeException as exception:
            response = interface.exception_response(exception)

            logger.error(f"Exception raised: '{type(exception).__name__}', response: '{response}'", exc_info=True)

            return response
        except Exception as exception:
            new_exception = InternalErrorException(exception)
            response = interface.exception_response(new_exception)

            logger.error(f"Exception raised: '{type(new_exception).__name__}', response: '{response}'", exc_info=True)

            return response
