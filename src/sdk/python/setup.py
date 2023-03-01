import io
import os
import json
import requests
import setuptools

readme_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../../README.md")
with io.open(os.path.abspath(readme_path), mode="r", encoding="utf-8") as fh:
    long_description = fh.read()

def get_version():
    resp = requests.get("https://pypi.org/pypi/appmesh/json")
    if resp.status_code == 200:
      data = json.loads(resp.text)
      if "info" in data and "version" in data["info"] :
        version = data["info"]["version"]
        version_list = list(str(int(version.replace(".", "")) + 1))
        while len(version_list) < 3:
            version_list = ["0"] + version_list
        return '.'.join(version_list)
    return "0.0.9"



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
    packages=["appmesh"],
    # requests for REST call
    # msgpack for TCP serialization
    # requests_toolbelt for MultipartEncoder
    # aniso8601 for ISO8601 duration parse
    install_requires=["requests", "msgpack", "requests_toolbelt", "aniso8601"],
    python_requires=">=3",
)
