import os.path

import setuptools

import stun


def main() -> None:
    src = os.path.realpath(os.path.dirname(__file__))
    readme = open(os.path.join(src, "README.rst")).read()

    setuptools.setup(
        name="stun",
        version=stun.__version__,
        packages=setuptools.find_packages(),
        zip_safe=False,
        license="MIT",
        author="John L. Villalovos",
        author_email="john@sodarock.com",
        url="https://github.com/JohnVillalovos/pystun",
        description=(
            "A Python STUN client for getting NAT type and external IP (RFC 3489)"
        ),
        long_description=readme,
        keywords="STUN NAT",
        classifiers=[
            "Development Status :: 4 - Beta",
            "License :: OSI Approved :: MIT License",
            "Programming Language :: Python :: 3",
            "Programming Language :: Python :: 3.6",
            "Programming Language :: Python :: 3.7",
            "Topic :: Internet",
            "Topic :: System :: Networking :: Firewalls",
        ],
        tests_require=["coverage", "nose", "prospector"],
        test_suite="tests",
        entry_points={"console_scripts": ["pystun=stun.cli:main"]},
    )


if __name__ == "__main__":
    main()
