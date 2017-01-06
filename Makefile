.PHONY: clean

vault-exec: *.go
	@go build -ldflags "-s -w"

clean:
	-@rm vault-exec
