all:
	go build

.PHONY: lint
lint:
	$(MAKE) -C gotools golangci-lint
	./gotools/golangci-lint run

.PHONY: spdx
spdx:
	./tools/spdx-ensure
