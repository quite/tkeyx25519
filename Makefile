all:
	go build

.PHONY: lint
lint:
	$(MAKE) -C gotools
	./gotools/golangci-lint run

.PHONY: spdx
spdx:
	./tools/spdx-ensure 
