# One command gates everything: `make check`.
#
# check = data integrity + format check + lint (zero warnings, all targets;
#         clippy also type-checks) + rustdoc warnings + tests under coverage
#         with a line-coverage threshold.

CARGO ?= cargo
COVERAGE_MIN ?= 80

.PHONY: check data-check fmt-check lint doc test coverage demo bench golden loc release clean

check: data-check fmt-check lint doc coverage
	@echo "make check: all gates passed"

data-check:
	./scripts/verify-data.sh

fmt-check:
	$(CARGO) fmt --all -- --check

lint:
	$(CARGO) clippy --locked --all-targets -- -D warnings

doc:
	RUSTDOCFLAGS="-D warnings" $(CARGO) doc --locked --no-deps

test:
	$(CARGO) test --locked

coverage:
	@command -v cargo-llvm-cov >/dev/null 2>&1 || { \
	  echo "cargo-llvm-cov is required: rustup component add llvm-tools-preview && cargo install cargo-llvm-cov --locked"; exit 1; }
	$(CARGO) llvm-cov --locked --summary-only --fail-under-lines $(COVERAGE_MIN)

release:
	$(CARGO) build --locked --release

demo: release
	./scripts/demo.sh

bench:
	./scripts/bench.sh

golden:
	./scripts/gen-golden.sh

loc:
	./scripts/loc.sh

clean:
	$(CARGO) clean
