.PHONY: all build run clean

# Go application settings
GO_APP_NAME = nis2-dash-backend
GO_MAIN_DIR = ./backend
GO_BUILD_DIR = ./build/backend

# React application settings
REACT_APP_NAME = nis2-dash-frontend
REACT_APP_DIR = ./frontend
REACT_BUILD_DIR = ./build/frontend

# Docker settings
DOCKER_COMPOSE_FILE = docker-compose.yml
DOCKER_IMAGE_PREFIX = nis2-dash

all: build

build: build-go build-react

build-go:
	@echo "Building Go application..."
	mkdir -p $(GO_BUILD_DIR)
	go build -o $(GO_BUILD_DIR)/$(GO_APP_NAME) $(GO_MAIN_DIR)

build-react:
	@echo "Building React application..."
	cd $(REACT_APP_DIR) && npm install
	cd $(REACT_APP_DIR) && npm run build
	mkdir -p $(REACT_BUILD_DIR)
	cp -r $(REACT_APP_DIR)/build/* $(REACT_BUILD_DIR)/

run:
	@echo "Running applications with Docker Compose..."
	docker-compose -f $(DOCKER_COMPOSE_FILE) up --build

clean:
	@echo "Cleaning up build directories and Docker images..."
	rm -rf $(GO_BUILD_DIR)
	rm -rf $(REACT_BUILD_DIR)
	docker-compose -f $(DOCKER_COMPOSE_FILE) down --rmi all
