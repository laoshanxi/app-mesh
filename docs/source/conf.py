import os
import sys
from shutil import copyfile
from recommonmark.parser import CommonMarkParser

# -- Path setup --------------------------------------------------------------
current_dir = os.path.dirname(os.path.realpath(__file__))
sdk_python_path = os.path.abspath(os.path.join(current_dir, "../../src/sdk/python"))
sys.path.insert(0, sdk_python_path)

# -- Project information -----------------------------------------------------
project = "AppMesh"
copyright = "2024, laoshanxi"
author = "laoshanxi"
release = "2.1.2"

# -- General configuration ---------------------------------------------------
needs_sphinx = "3.0"
extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.intersphinx",
    "sphinx.ext.napoleon",
    "sphinx.ext.extlinks",
    "sphinx.ext.viewcode",
    "sphinxcontrib.apidoc",
    "sphinx_markdown_tables",
    "sphinx_autodoc_typehints",
    "recommonmark",
]

# apidoc configuration
apidoc_module_dir = sdk_python_path
apidoc_output_dir = "api"
apidoc_excluded_paths = ["test"]
apidoc_separate_modules = False
apidoc_toc_file = False
autoclass_content = "both"

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

# -- Options for HTML output -------------------------------------------------
html_theme = "sphinx_rtd_theme"
html_static_path = ["_static"]

# -- Markdown support --------------------------------------------------------
source_parsers = {".md": CommonMarkParser}
source_suffix = [".rst", ".md"]

# -- Copy necessary files ----------------------------------------------------
readme_src = os.path.join(current_dir, "../../README.md")
readme_dest = os.path.join(current_dir, "README.md")
appmesh_client_src = os.path.join(current_dir, "../../src/sdk/python/appmesh/appmesh_client.py")
appmesh_client_dest = os.path.join(current_dir, "../../src/sdk/python/appmesh_client.py")

copyfile(readme_src, readme_dest)
copyfile(appmesh_client_src, appmesh_client_dest)

# -- Exclude specific Python files -------------------------------------------
exclude_py_files = [os.path.join(sdk_python_path, "py_exec.py"), os.path.join(sdk_python_path, "setup.py")]
for f in exclude_py_files:
    os.path.exists(f) and os.remove(f)
