.PHONY: publish

publish:
	cargo publish -p cgroup_traffic
	cargo publish -p socket_filter