# -*- coding: utf-8 -*-
from distutils.core import setup

setup(
    name='askhomeng',
    packages=['askhomeng'],
    version='0.1.0',
    author=u'Claudio Pastorini',
    author_email='claudio.pastorini@powahome.com',
    url='https://github.com/claudiopastorini/askhomeng',
    download_url='https://github.com/claudiopastorini/askhomeng/archive/0.1.tar.gz',
    keywords='',
    description='Alexa Skills Kit library for working with Smart Home Skill API',
    install_requires=[
        'inflection',
        'requests'
    ],
)
