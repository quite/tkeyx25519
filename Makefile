all:
	go build

golangci_version=$(shell grep -A2 "uses: golangci" .github/workflows/ci.yaml | grep -o -m1 "v[0-9]\+\.[.0-9]\+")
golangci_cachedir=$(HOME)/.cache/golangci-lint/$(golangci_version)
.PHONY: lint
lint:
	mkdir -p $(golangci_cachedir)
	podman run --rm -it \
		-v $$(pwd):/src -w /src \
		-v $(golangci_cachedir):/root/.cache \
		docker.io/golangci/golangci-lint:$(golangci_version)-alpine \
		golangci-lint run

.PHONY: spdx
spdx:
	./tools/spdx-ensure
