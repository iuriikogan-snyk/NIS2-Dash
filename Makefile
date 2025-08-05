# Makefile for building, running, and cleaning the NIS2 Dashboard application.

.PHONY: all build build-go build-react run clean


# --- Application Settings ---
GO_APP_NAME := nis2-dash-backend
GO_MAIN_DIR := ./backend/cmd
GO_BUILD_DIR := ./build/backend

REACT_APP_DIR := ./frontend

# --- Docker Settings ---
DOCKER_COMPOSE_FILE := docker-compose.yml

# Default target runs the 'build' target.
all: build

# Builds both the Go and React applications locally.
build: build-go build-react

# Compiles the Go application into the build directory.
# The path is corrected to point to the root of the backend module.
build-go:
	@echo "--> Building Go application..."
	@mkdir -p $(GO_BUILD_DIR)
	go build -o $(GO_BUILD_DIR)/$(GO_APP_NAME) $(GO_MAIN_DIR)

# Prepares the React application by installing dependencies.
# The 'npm run build' step is not strictly necessary here, as the
# Dockerfile will handle the production build. This is for local verification.
build-react:
	@echo "--> Building React application..."
	cd $(REACT_APP_DIR) && npm install && npm run build

# Runs the application stack using Docker Compose.
# The '--build' flag ensures images are rebuilt if anything has changed.
run:
	@echo "--> Running applications with Docker Compose..."
	docker-compose -f $(DOCKER_COMPOSE_FILE) up

# Cleans up build artifacts and stops/removes Docker containers and images.
clean:
	@echo "--> Cleaning up..."
	@rm -rf $(GO_BUILD_DIR)
	@rm -rf $(REACT_APP_DIR)/build
	@docker-compose -f $(DOCKER_COMPOSE_FILE) down --rmi all -v --remove-orphans

