.PHONY: tests
SHELL := /usr/bin/bash
.ONESHELL:


help:
	@printf "\ninstall\n\tinstall requirements\n"
	@printf "\nisort\n\tmake isort import corrections\n"
	@printf "\nlint\n\tmake linter check with black\n"
	@printf "\ntcheck\n\tmake static type checks with mypy\n"
	@printf "\ntests\n\tLaunch tests\n"
	@printf "\nprepare\n\tLaunch tests and commit-checks\n"
	@printf "\ncommit-checks\n\trun pre-commit checks on all files\n"
	# @printf "\nbuild \n\tbuild docker image\n"

venv_activated=if [ -z $${VIRTUAL_ENV+x} ]; then printf "activating venv...\n" ; source venv/bin/activate ; else printf "venv already activated\n"; fi

install: venv

venv: venv/touchfile

venv/touchfile: requirements.txt requirements-dev.txt
	test -d venv || python3.10 -m venv
	source venv/bin/activate
	pip install -r requirements-dev.txt
	touch venv/touchfile


tests: venv
	@$(venv_activated)
	pytest .

lint: venv
	@$(venv_activated)
	black -l 120 .

isort: venv
	@$(venv_activated)
	isort .

tcheck: venv
	@$(venv_activated)
	mypy jwtjwkhelper

.git/hooks/pre-commit: venv
	@$(venv_activated)
	pre-commit install

commit-checks: .git/hooks/pre-commit
	@$(venv_activated)
	pre-commit run --all-files

prepare: tests commit-checks


pypibuild: venv
	@$(venv_activated)
	pip install -r requirements-build.txt
	pip install --upgrade twine build
	python3 -m build


#	python3 -m twine upload --repository pypi dist/*

# UPLOAD:
# python3 -m twine upload --repository testpypi dist/*
#python3 -m pip install --index-url https://test.pypi.org/simple/ --no-deps example-package-YOUR-USERNAME-HERE
#python3 -m pip install --index-url https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ jwtjwkhelper-vroomfondel==0.0.2

