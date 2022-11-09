import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="aioairctrl",
    version="0.2.6",
    description="Library for controlling Philips air purifiers (using encrypted CoAP)",
    long_description=long_description,
    author="betaboon",
    url="https://github.com/rimonhanna/aioairctrl",
    project_urls={
        "Bug Tracker": "https://github.com/rimonhanna/aioairctrl/issues",
    },
    license="MIT",
    package_dir={"": "."},
    packages=setuptools.find_packages(),
    install_requires=[
        "pycryptodomex",
        "aiocoap>=0.4.4, <0.5",
    ],
    python_requires=">=3.6",
    entry_points={
        "console_scripts": [
            "aioairctrl=aioairctrl.__main__:main",
        ],
    },
)
