.PHONY: build test clean run demo query help

# Default target
help:
	@echo "HostWatch - Network Host Discovery Tool"
	@echo "======================================"
	@echo ""
	@echo "Available commands:"
	@echo "  build     - Build the application in release mode"
	@echo "  test      - Run all tests"
	@echo "  clean     - Clean build artifacts"
	@echo "  run       - Run the application (requires sudo)"
	@echo "  help      - Show this help message"
	@echo ""

# Build the application in release mode
build:
	cargo build --release

# Run tests
test:
	cargo test

# Clean build artifacts
clean:
	cargo clean

# Run the application (requires sudo)
run: build
	sudo ./target/release/hostwatch

# Run with specific interface
run-interface: build
	@read -p "Enter interface name: " interface; \
	sudo ./target/release/hostwatch -i $$interface

# Check if running as root
check-root:
	@if [ "$$(id -u)" != "0" ]; then \
		echo "Error: This command requires root privileges"; \
		echo "Please run with sudo"; \
		exit 1; \
	fi

# Show network interfaces
interfaces:
	@echo "Available network interfaces:"
	@ifconfig | grep -E "^[a-zA-Z0-9]+:" | cut -d: -f1 | sort

# Show help for command line options
help-options: build
	./target/release/hostwatch --help
