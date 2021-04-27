from setuptools import setup


setup(
    name="r2sim",
    version="0.0.1",
    description="Comparing similarities between two files using radare2 backend.",
    author="W3ndige",
    author_email="w3ndige@gmail.com",
    packages=["r2sim"],
    url="https://github.com/W3ndige/r2sim",
    include_package_data=True,
    install_requires=open("requirements.txt").read().splitlines(),
    python_requires=">=3.6",
    entry_points={
        "console_scripts": [
            "r2sim = r2sim.interface:main_interface",
        ]
    },
    zip_safe=False,
    classifiers=[
        "Development Status :: 3 - Alpha",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Programming Language :: Python :: 3",
    ],
)
