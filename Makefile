.PHONY: isort
isort:
	  isort .

.PHONY: test
test:
	  python3 -m pytest . -v

.PHONY: flake8
flake8:
	  python3 -m flake8 .

.PHONY: clean-build
clean-build:
	  rm -rf *.egg-info dist build

.PHONY: clean-pyc
clean-pyc:
	  find . -name '*.pyc' -delete
	  find . -name '*.pyo' -delete

.PHONY: trim
trim:
	  trim .

.PHONY: unify
unify:
	  unify -r -i --quote '"' .

.PHONY: trail-comma
trail-comma:
	  find . -name '*.py' -exec add-trailing-comma {} +

.PHONY: lint
lint:
	sh -c "isort . "
	unify -r -i --quote '"' .
	trim .
	find . -name '*.py' -exec add-trailing-comma {} +
