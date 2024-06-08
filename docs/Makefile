all:
	python3 -m venv venv
	venv/bin/pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple
	venv/bin/python -m pip install --upgrade pip setuptools
	venv/bin/python -m pip install --upgrade sphinx readthedocs-sphinx-ext
	venv/bin/python -m pip install -r ./requirements.txt
	venv/bin/python -m pip install appmesh
	venv/bin/python source/conf.py
	venv/bin/python -m sphinx -T -E -b html -d _build/doctrees -D language=en ./source _build/html

dep:
	pip3 install virtualenv

docker:
	- docker rm -f readthedoc
	docker run -d --name readthedoc -p 80:80 -v `pwd`/_build/html:/usr/share/nginx/html nginx:mainline-alpine
