# Domain Scanner Makefile
# 域名扫描器编译脚本

# 项目信息
BINARY_NAME=domain-scanner
VERSION=v1.3.2
BUILD_TIME=$(shell date +%Y-%m-%d_%H:%M:%S)
GIT_COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Go 编译参数
LDFLAGS=-ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME) -X main.GitCommit=$(GIT_COMMIT)"

# 目标平台
PLATFORMS=linux/amd64 linux/arm64 windows/amd64 windows/arm64 darwin/amd64 darwin/arm64

# 默认目标
.PHONY: all
all: clean build

# 清理编译产物
.PHONY: clean
clean:
	@echo "🧹 清理编译产物..."
	@rm -rf dist/
	@rm -f $(BINARY_NAME) $(BINARY_NAME).exe
	@rm -f $(BINARY_NAME)-*

# 安装依赖
.PHONY: deps
deps:
	@echo "📦 安装依赖..."
	@go mod tidy
	@go mod download

# 代码检查
.PHONY: lint
lint:
	@echo "🔍 代码检查..."
	@go vet ./...
	@go fmt ./...

# 运行测试
.PHONY: test
test:
	@echo "🧪 运行测试..."
	@go test -v ./...

# 编译当前平台
.PHONY: build
build: deps lint
	@echo "🔨 编译当前平台版本..."
	@go build $(LDFLAGS) -o $(BINARY_NAME) .
	@echo "✅ 编译完成: $(BINARY_NAME)"

# 编译所有平台
.PHONY: build-all
build-all: deps lint
	@echo "🔨 编译所有平台版本..."
	@mkdir -p dist
	@for platform in $(PLATFORMS); do \
		GOOS=$$(echo $$platform | cut -d'/' -f1); \
		GOARCH=$$(echo $$platform | cut -d'/' -f2); \
		output_name=$(BINARY_NAME)-$$GOOS-$$GOARCH; \
		if [ $$GOOS = "windows" ]; then output_name=$$output_name.exe; fi; \
		echo "📦 编译 $$GOOS/$$GOARCH..."; \
		GOOS=$$GOOS GOARCH=$$GOARCH go build $(LDFLAGS) -o dist/$$output_name .; \
		if [ $$? -eq 0 ]; then \
			echo "✅ $$output_name 编译成功"; \
		else \
			echo "❌ $$output_name 编译失败"; \
		fi; \
	done
	@echo "🎉 所有平台编译完成，文件位于 dist/ 目录"

# 编译并运行
.PHONY: run
run: build
	@echo "🚀 运行程序..."
	@./$(BINARY_NAME) -h

# 生成批量配置
.PHONY: gen-config
gen-config:
	@echo "⚙️ 生成批量配置文件..."
	@go run utils/generate_batch_configs.go -batch-start 0 -batch-size 26 -base-domain .de -domain-length 4 -pattern D

# 开发模式运行
.PHONY: dev
dev:
	@echo "🔧 开发模式运行..."
	@go run main.go -config config/config.toml

# 显示版本信息
.PHONY: version
version:
	@echo "域名扫描器 $(VERSION)"
	@echo "构建时间: $(BUILD_TIME)"
	@echo "Git提交: $(GIT_COMMIT)"

# 显示帮助
.PHONY: help
help:
	@echo "域名扫描器 Makefile 使用说明"
	@echo ""
	@echo "可用命令:"
	@echo "  make build      - 编译当前平台版本"
	@echo "  make build-all  - 编译所有平台版本"
	@echo "  make clean      - 清理编译产物"
	@echo "  make deps       - 安装依赖"
	@echo "  make lint       - 代码检查"
	@echo "  make test       - 运行测试"
	@echo "  make run        - 编译并运行"
	@echo "  make dev        - 开发模式运行"
	@echo "  make gen-config - 生成批量配置文件"
	@echo "  make version    - 显示版本信息"
	@echo "  make help       - 显示此帮助信息"
	@echo ""
	@echo "示例:"
	@echo "  make build-all  # 编译所有平台版本"
	@echo "  make dev        # 使用配置文件运行"

# 安装到系统
.PHONY: install
install: build
	@echo "📥 安装到系统..."
	@sudo cp $(BINARY_NAME) /usr/local/bin/
	@echo "✅ 安装完成，可以在任意位置使用 $(BINARY_NAME) 命令"

# 卸载
.PHONY: uninstall
uninstall:
	@echo "🗑️ 从系统卸载..."
	@sudo rm -f /usr/local/bin/$(BINARY_NAME)
	@echo "✅ 卸载完成"
