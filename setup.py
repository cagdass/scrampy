#!/usr/bin/env python3

from setuptools import setup, find_packages

setup(name='Scrampy',
     version='0.0.1',
     description='Pundun Client',
     author='Cagdas',
     author_email="cagdas@a.b",
     url='https://www.pundun.io',
     license='Apache License 2.0',
     packages=find_packages(exclude=["tests*"])
    )
