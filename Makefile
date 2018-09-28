-include artifacts/make/go/Makefile

artifacts/make/%/Makefile:
	curl -sf https://jmalloc.github.io/makefiles/fetch | bash /dev/stdin $*

.PHONY: docker-lint
docker-lint: vendor $(_SRC) $(REQ) | $(MISSPELL) $(GOMETALINTER) $(USE)
	$(RM) artifacts/logs/lint
	docker run -ti --rm \
		-v $(shell pwd):/go/src/$(subst $(dir $(patsubst %/,%,$(dir $(patsubst %/,%,$(dir $(CURDIR)))))),,$(CURDIR)) \
		--workdir /go/src/$(subst $(dir $(patsubst %/,%,$(dir $(patsubst %/,%,$(dir $(CURDIR)))))),,$(CURDIR)) \
		golang:1.10 \
		make lint

.PHONY: run-example
run-example: vendor
	cd src/example && go run main.go
