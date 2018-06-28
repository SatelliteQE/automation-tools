# Commands --------------------------------------------------------------------

help:
	@echo "Please use \`make <target>' where <target> is one of"
	@echo "  docs                       to make documentation in the default format"
	@echo "  docs-clean                 to remove docs and doc build artifacts"
	@echo "  pyc-clean                  to delete all temporary artifacts"
	@echo "  can-i-push?                to check if local changes are suitable to push"
	@echo "  install-commit-hook        to install pre-commit hook to check if changes are suitable to push"
	@echo "  gitflake8                  to check flake8 styling only for modified files"

docs:
	@cd docs; $(MAKE) html

docs-clean:
	@cd docs; $(MAKE) clean

pyc-clean: ## remove Python file artifacts
	$(info "Removing unused Python compiled files, caches and ~ backups...")
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +
	find . -name '__pycache__' -exec rm -fr {} +

gitflake8:
	$(info "Checking style and syntax errors with flake8 linter...")
	@which flake8 >> /dev/null || pip install flake8
	@flake8 $(shell git diff --name-only) --show-source --exclude=Makefile,*.yml 

can-i-push?: gitflake8
	$(info "!!! Congratulations your changes are good to fly, make a great PR! ${USER}++ !!!")

install-commit-hook:
	$(info "Installing git pre-commit hook...")
	@touch .git/hooks/pre-commit
	@grep -q '^make can-i-push?' .git/hooks/pre-commit || echo "make can-i-push?" >> .git/hooks/pre-commit

# Special Targets -------------------------------------------------------------

.PHONY: help docs docs-clean pyc-clean can-i-push? install-commit-hook gitflake8
