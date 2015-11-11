#!/usr/bin/env python
# -*- coding: utf-8 -*-

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

with open('README.rst', 'r') as f:
    readme = f.read()

setup(
    name='automation_tools',
    version='0.1.0',
    description='Tools to help automating testing Foreman with Robottelo.',
    long_description=readme,
    author=u'Elyézer Rezende',
    author_email='erezende@redhat.com',
    url='https://github.com/SatelliteQE/automation-tools',
    packages=['automation_tools'],
    package_data={'': ['LICENSE']},
    package_dir={'automation_tools': 'automation_tools'},
    include_package_data=True,
    install_requires=['Fabric', 'lxml', 'python-novaclient', 'requests'],
    license='GNU GPL v3.0',
    classifiers=(
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
    ),
)
