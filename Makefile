.PHONY: log, vectorize

log:
	mkdir -p build/
	go build -o ./build/wgr .
	./build/wgr &

vectorize:
	vector --openssl-legacy-provider=false -q --config ./vector/vector.toml | jq