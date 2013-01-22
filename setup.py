from setuptools import setup

VERSION = '0.1.0'

setup(
    name="chevah-txftps",
    version=VERSION,
    description=meta.description,
    author='Adi Roiban',
    author_email='adi.roiban@chevah.com',
    url='http://www.chevah.com',
    license='BSD 3-Clause',
    packages=['chevah', 'chevah.txftps'],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Programming Language :: Python",
        ],
    )
