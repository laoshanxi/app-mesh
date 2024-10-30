import io
import os
import setuptools

readme_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../../README.md")
with io.open(os.path.abspath(readme_path), mode="r", encoding="utf-8") as fh:
    long_description = fh.read()


def get_version():
    """PyPI package version"""
    return "1.3.5"


setuptools.setup(
    name="appmesh",
    version=get_version(),
    author="laoshanxi",
    author_email="178029200@qq.com",
    description="Client SDK for App Mesh",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/laoshanxi/app-mesh",
    license="MIT",
    keywords="appmesh AppMesh app-mesh",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    packages=setuptools.find_packages(exclude=["test*"]),
    # requests for REST call
    # msgpack for TCP serialization
    # requests_toolbelt for MultipartEncoder
    # aniso8601 for ISO8601 duration parse
    install_requires=["requests", "msgpack", "requests_toolbelt", "aniso8601"],
    python_requires=">=3",
)
