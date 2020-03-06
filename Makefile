-include .makefiles/Makefile
-include .makefiles/pkg/go/v1/Makefile

.makefiles/%:
	@curl -sfL https://makefiles.dev/v1 | bash /dev/stdin "$@"

.PHONY: docker-test
docker-test: $(GO_SOURCE_FILES) $(GENERATED_FILES)
	$(RM) artifacts/logs/docker-test
	@mkdir -p artifacts/.makefiles
	docker run -ti --rm \
		-v "$(shell pwd):/code" \
		-v "$(shell pwd)/artifacts/.makefiles:/code/.makefiles" \
		--workdir /code \
		golang:1.14-alpine \
		sh -c 'apk --update add git make curl bash util-linux zip libc-dev gcc; make test'

######################
# Linting
######################

MISSPELL := artifacts/misspell/bin/misspell
$(MISSPELL):
	@mkdir -p "$(MF_PROJECT_ROOT)/$(@D)"
	GOBIN="$(MF_PROJECT_ROOT)/$(@D)" go get -modfile tools.mod github.com/client9/misspell/cmd/misspell

GOLANGCILINT := artifacts/golangci-lint/bin/golangci-lint
$(GOLANGCILINT):
	@mkdir -p "$(MF_PROJECT_ROOT)/$(@D)"
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b "$(MF_PROJECT_ROOT)/$(@D)" v1.23.8

# STATICCHECK := artifacts/staticcheck/bin/staticcheck
# $(STATICCHECK):
# 	@mkdir -p "$(MF_PROJECT_ROOT)/$(@D)"
# 	GOBIN="$(MF_PROJECT_ROOT)/$(@D)" go get -modfile tools.mod honnef.co/go/tools/cmd/staticcheck

.PHONY: lint
lint:: $(MISSPELL) $(GOLANGCILINT) $(STATICCHECK)
	go vet ./...
	golint -set_exit_status ./...
	$(MISSPELL) -w -error -locale UK ./...
	$(GOLANGCILINT) run --enable-all ./...
