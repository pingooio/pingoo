DIST_DIR = dist
COMMIT := $(shell git rev-parse HEAD)
DOCKER_IMAGE = docker.io/pingooio/pingoo
VERSION := $(shell cat Cargo.toml | grep '^version =' | cut -d'"' -f2)

####################################################################################################
# Dev
####################################################################################################

.PHONY: dev
dev:
	cargo run -p pingoo


.PHONY: fmt
fmt:
	cargo fmt

.PHONY: check
check:
	cargo check

.PHONY: clean
clean:
	rm -rf $(DIST_DIR) captcha/dist


.PHONY: update_deps
update_deps:
	cargo update


.PHONY: release
release:
	date
	git checkout main
	git push
	git tag v$(VERSION)
	git push --tags
	git checkout release
	git merge main
	git push
	git checkout main


.PHONY: compress_geoip_db
compress_geoip_db:
	mkdir -p $(DIST_DIR)
	zstd --ultra -19 --force --check geoip.mmdb
	mv geoip.mmdb.zst $(DIST_DIR)

####################################################################################################
# Build
####################################################################################################
.PHONY: build
build:
	mkdir -p $(DIST_DIR)
	cargo build -p pingoo --release
	cp target/release/pingoo $(DIST_DIR)/
	strip --strip-all -xX $(DIST_DIR)/pingoo


.PHONY: docker_build
docker_build:
	docker build -t $(DOCKER_IMAGE):latest -f Dockerfile .
	docker tag $(DOCKER_IMAGE):latest $(DOCKER_IMAGE):$(VERSION)


.PHONY: docker_push
docker_push:
	docker push $(DOCKER_IMAGE):latest $(DOCKER_IMAGE):$(VERSION)
