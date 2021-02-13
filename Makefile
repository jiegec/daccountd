.PNONY: all clean

all: target/bindings.rs target/libdaccountd.a

target/bindings.rs: target/libdaccountd.a
	bindgen target/libdaccountd.h -o $@

target/libdaccountd.a: go/etcd.go
	CGO_ENABLED=1 go build -buildmode=c-archive -o $@ $^

clean:
	rm -rf target/libdaccountd.a target/libdaccountd.h target/bindings.rs