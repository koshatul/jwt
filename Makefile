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
		golang:1.13-alpine \
		sh -c 'apk --update add git make curl bash util-linux zip libc-dev gcc; make test'
