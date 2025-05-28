
bump-verson:
	cargo ws version --no-individual-tags

clean-ice:
	trash rustc-ice-2025*.txt

build:
	cargo build

test-arp: build
	sudo setcap cap_net_raw+ep ./target/debug/arp
	cargo run --bin arp -- 192.168.31.226 192.168.31.106 192.168.31.187 110.242.68.66

test-ping: build
	@ sudo setcap cap_net_raw+eip ./target/debug/ping
	@ # cargo run --bin ping -- 2.2.1.1  # test unreach dest
	@ # cargo run --bin ping -- localhost
	cargo run --bin ping -- baidu.com
