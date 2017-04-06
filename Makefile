.PHONY: default build clean vendor

DST=$(GOPATH)/bin/vault-exec

default: build

build: $(DST)

$(DST): $(shell find . -name "*.go" -print)
	@go build -i  -ldflags "-s -w" -o $(DST) mediafly/vault-exec/main

clean:
	-@rm $(DST)

vendor:
	@govendor fetch -v +vendor +missing
