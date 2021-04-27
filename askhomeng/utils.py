import re

import inflection


def get_interface_string(func_name):
    """Transform function name to Alexa interface"""
    return f"Alexa.{rstrip_word(lstrip_word(inflection.camelize(func_name), 'Alexa.'), 'Interface')}"


def get_directive_string(func_name):
    """Transform function name to Alexa directive name"""
    return inflection.camelize(func_name)


def rstrip_word(text, suffix):
    """Strip suffix from end of text"""
    if not text.endswith(suffix):
        return text
    return text[:len(text) - len(suffix)]


def lstrip_word(text, prefix):
    """Strip prefix from end of text"""
    if not text.startswith(prefix):
        return text
    return text[len(prefix):len(text)]


def camel_to_snake(name):
    name = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', name).lower()
