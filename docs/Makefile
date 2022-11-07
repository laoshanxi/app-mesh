all:
	python3 -mvirtualenv venv
	venv/bin/python -m pip install --upgrade pip setuptools
	venv/bin/python -m pip install --upgrade pillow mock==1.0.1 alabaster commonmark==0.9.1 recommonmark==0.5.0 sphinx sphinx-rtd-theme readthedocs-sphinx-ext
	venv/bin/python -m pip install --exists-action=w -r ../requirements.txt
	venv/bin/python source/conf.py
	venv/bin/python -m sphinx -T -E -b html -d _build/doctrees -D language=en ./source _build/html

dep:
	pip3 install virtualenv

docker:
	- docker rm -f readthedoc
	docker run -d --name readthedoc -p 80:80 -v `pwd`/_build/html:/usr/share/nginx/html nginx:mainline-alpine
