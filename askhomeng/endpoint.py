from enum import Enum

from .utils import get_directive_string
from .utils import get_interface_string


class _classproperty(property):
    """Utility class for @property fields on the class."""

    def __init__(self, func):
        self.func = func
        self.__doc__ = func.__doc__

    def __get__(self, instance, owner):
        # This makes docstrings work
        if owner is Endpoint:
            return self
        return self.func(owner)


class Categories(Enum):
    ACTIVITY_TRIGGER = "A combination of devices set to a specific state. Use activity triggers for scenes when the state changes must occur in a specific order. For example, for a scene named \"watch Netflix\" you might power on the TV first, and then set the input to HDMI1."
    AIR_FRESHENER = "A device that emits pleasant odors and masks unpleasant odors in interior spaces."
    AIR_PURIFIER = "A device that improves the quality of air in interior spaces."
    AUTO_ACCESSORY = "A smart device in an automobile, such as a dash camera."
    CAMERA = "A security device with video or photo functionality."
    CHRISTMAS_TREE = "A religious holiday decoration that often contains lights."
    COFFEE_MAKER = "A device that makes coffee."
    COMPUTER = "A non-mobile computer, such as a desktop computer."
    CONTACT_SENSOR = "An endpoint that detects and reports changes in contact between two surfaces."
    DOOR = "A door."
    DOORBELL = "A doorbell."
    EXTERIOR_BLIND = "A window covering, such as blinds or shades, on the outside of a structure."
    FAN = "A fan."
    GAME_CONSOLE = "A game console, such as Microsoft Xbox or Nintendo Switch"
    GARAGE_DOOR = "A garage door. Garage doors must implement the ModeController interface to open and close the door."
    HEADPHONES = "A wearable device that transmits audio directly into the ear."
    HUB = "A smart-home hub."
    INTERIOR_BLIND = "A window covering, such as blinds or shades, on the inside of a structure."
    LAPTOP = "A laptop or other mobile computer."
    LIGHT = "A light source or fixture."
    MICROWAVE = "A microwave oven."
    MOBILE_PHONE = "A mobile phone."
    MOTION_SENSOR = "An endpoint that detects and reports movement in an area."
    MUSIC_SYSTEM = "A network-connected music system."
    NETWORK_HARDWARE = "A network router."
    OTHER = "An endpoint that doesn't belong to one of the other categories."
    OVEN = "An oven cooking appliance."
    PHONE = "A non-mobile phone, such as landline or an IP phone."
    PRINTER = "A device that prints."
    ROUTER = "A network router."
    SCENE_TRIGGER = "A combination of devices set to a specific state. Use scene triggers for scenes when the order of the state change is not important. For example, for a scene named \"bedtime\" you might turn off the lights and lower the thermostat, in any order."
    SCREEN = "A projector screen."
    SECURITY_PANEL = "A security panel."
    SECURITY_SYSTEM = "A security system."
    SLOW_COOKER = "An electric cooking device that sits on a countertop, cooks at low temperatures, and is often shaped like a cooking pot."
    SMARTLOCK = "An endpoint that locks."
    SMARTPLUG = "A module that is plugged into an existing electrical outlet, and then has a device plugged into it. For example, a user can plug a smart plug into an outlet, and then plug a lamp into the smart plug. A smart plug can control a variety of devices."
    SPEAKER = "A speaker or speaker system."
    STREAMING_DEVICE = "A streaming device such as Apple TV, Chromecast, or Roku."
    SWITCH = "A switch wired directly to the electrical system. A switch can control a variety of devices."
    TABLET = "A tablet computer."
    TEMPERATURE_SENSOR = "An endpoint that reports temperature, but does not control it. The temperature data of the endpoint doesn't appear in the Alexa app. If your endpoint also controls temperature, use THERMOSTAT instead."
    THERMOSTAT = "An endpoint that controls temperature, stand-alone air conditioners, or heaters with direct temperature control. If your endpoint senses temperature but does not control it, use TEMPERATURE_SENSOR instead."
    TV = "A television."
    VACUUM_CLEANER = "A vacuum cleaner."
    VEHICLE = "A motor vehicle (automobile, car)."
    WATER_HEATER = "A device that heats water, often consisting of a large tank."
    WEARABLE = "A network-connected wearable device, such as an Apple Watch, Fitbit, or Samsung Gear."


class Endpoint(object):
    """Endpoint subclasses are used to describe what interfaces devices support.

    Methods of subclasses can be marked with decorators (like ``@Endpoint.interface``) and are used to
    generate the Alexa DiscoverEndpointResponse. Alexa control and query requests are then routed
    to the corresponding decorated method.

    Endpoint subclass can also contain a ``Details`` inner class for instance defaults during
    discovery (see ``Smarthome.add_endpoint`` for possible attributes).

    Attributes:
        request (Request): Currently processed request.
        id (str): Identifier of the endpoint from the endpoint.endpointId of request payload.
        additional_details (dict): Information that was sent for the DiscoverEndpointsRequest.
            Some instance specific details can be saved here.

    """

    def __init__(self, request=None):
        """Endpoint gets initialized just before its interface methods are called. Put your
        logic for preparation before handling the request here.
        """
        if request is not None:
            self.request = request
            self.id = request.endpoint.get('endpointId')

        self.needToSendEndpointHealth = True if 'Alexa.EndpointHealth' in self.capabilities.keys() else False

    @classmethod
    def interface(cls, properties=[], proactively_reported=False, retrievable=False, supported_operations=[], instance=None, capability_resources=None, configuration=None, semantics=None):
        """Decorator for marking the method as an interface sent for the DiscoverEndpointsRequest.



        """
        supported_operations = [get_directive_string(supported_operation) for supported_operation in supported_operations]

        def decorator(func):
            last = getattr(func, 'ask_interfaces', [])
            func.ask_interfaces = last + [{'name': get_interface_string(func.__name__), 'properties': properties, 'proactively_reported': proactively_reported, 'retrievable': retrievable, 'supported_operations': supported_operations, 'instance': instance, 'capability_resources': capability_resources, 'configuration': configuration, 'semantics': semantics}]
            return func

        return decorator

    @classmethod
    def interface_directive(cls, interface_name, properties=[], proactively_reported=False, retrievable=False, instance=None, capability_resources=None, configuration=None, semantics=None):
        """Decorator for marking the method as an interface sent for the DiscoverEndpointsRequest.



        """
        def decorator(func):
            last = getattr(func, 'ask_interfaces', [])
            func.ask_interfaces = last + [{'name': get_interface_string(interface_name), 'properties': properties, 'proactively_reported': proactively_reported, 'retrievable': retrievable, 'supported_operations': [get_directive_string(func.__name__)], 'instance': instance, 'capability_resources': capability_resources, 'configuration': configuration, 'semantics': semantics}]
            return func

        return decorator

    @_classproperty
    def interfaces(cls):
        """dict(str, function): All interfaces the endpoint supports and their corresponding (unbound)
        method references. Action names are formatted for the DiscoverEndpointsRequest.
        """
        ret = {}
        for supercls in cls.__mro__:  # This makes inherited Endpoints work
            for method in supercls.__dict__.values():
                for interface in getattr(method, 'ask_interfaces', []):
                    ret[interface['name']] = method

        return ret

    @_classproperty
    def capabilities(cls):
        """dict(str, function): All interfaces the endpoint supports and their corresponding (unbound)
        method references. Action names are formatted for the DiscoverEndpointsRequest.
        """
        capabilities = {}
        for supercls in cls.__mro__:  # This makes inherited Endpoints work
            for method in supercls.__dict__.values():
                for interface in getattr(method, 'ask_interfaces', []):
                    capabilities[interface['name']] = interface

        return capabilities

    @_classproperty
    def properties(cls):
        """dict(str, function): All interfaces the endpoint supports and their corresponding (unbound)
        method references. Action names are formatted for the DiscoverEndpointsRequest.
        """
        properties = {
            'retrievable': {},
            'proactively_reported': {}
        }

        for supercls in cls.__mro__:  # This makes inherited Endpoints work
            for method in supercls.__dict__.values():
                for interface in getattr(method, 'ask_interfaces', []):
                    if interface['retrievable']:
                        properties['retrievable'][get_interface_string(interface['name'])] = interface['properties']

                    if interface['proactively_reported']:
                        properties['proactively_reported'][get_interface_string(interface['name'])] = interface['properties']

        return properties

    @_classproperty
    def directive_handlers(cls):
        """dict(str, function): All requests the endpoint supports (methods marked as interfaces)
        and their corresponding (unbound) method references. For example interface turn_on would be
        formatted as TurnOnRequest.
        """
        ret = {}
        for supercls in cls.__mro__:  # This makes inherited Endpoints work
            for method in supercls.__dict__.values():
                if not hasattr(method, '__call__'):
                    continue

                ret[get_directive_string(method.__name__)] = method

        return ret

    @_classproperty
    def interface_handlers(cls):
        """dict(str, function): All requests the endpoint supports (methods marked as interfaces)
        and their corresponding (unbound) method references. For example interface turn_on would be
        formatted as TurnOnRequest.
        """
        ret = {}
        for supercls in cls.__mro__:  # This makes inherited Endpoints work
            for method in supercls.__dict__.values():
                for interface in getattr(method, 'ask_interfaces', []):
                    ret[get_interface_string(interface['name'])] = method

        return ret

    class Details:
        """Inner class in ``Endpoint`` subclasses provides default values so that they don't
        have to be repeated in ``Smarthome.add_endpoint``.
        """
