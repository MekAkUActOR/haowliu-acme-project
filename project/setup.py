from setuptools import setup

setup(
    name="ACME_Project",
    version="1.0",
    description="ACME project",
    author="Haowen Liu",
    author_email="haowliu@student.ethz.ch",
    license="MIT",
    install_requires=[
        "dnslib==0.9.23",
        "requests==2.28.1"
        "cryptography==38.0.3"
        "Flask==2.2.2"
    ],
)