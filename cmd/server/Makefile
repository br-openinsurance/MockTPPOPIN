# Makefile
#

.PHONY: checks clean build build-local test test-and-report

include ../../version.properties
VER=${VERSION}

ifdef CHANGE_ID
VER=PR-${CHANGE_ID}-SNAPSHOT
else
VER=${VERSION}.${BUILD_NUMBER}
endif

PKG=github.com/raidiam/oibrazil-mock-tpp/application
REPO_INFO=$(shell git config --get remote.origin.url)
DATE=$(shell date)

LDFLAGS=-X "$(PKG).Version=$(VER)" -X "$(PKG).BuildDate=$(DATE)" -X "$(PKG).RepoUrl=$(REPO_INFO)" -X "$(PKG).BuildUrl=$(BUILD_URL)"

checks:
	@staticcheck ./...
	@gosec ./...
	@go fmt ./...

clean:
	@( rm -f main tpp-${VER}-application-function.zip)

build:
	@rm -f bootstrap tpp-${VER}-application-function.zip
	@(GOARCH=arm64 GOOS=linux go build -ldflags '-s -w $(LDFLAGS)' -gcflags "all=-trimpath=$GOPATH" -o bootstrap && zip tpp-${VER}-application-function.zip bootstrap)

build-local:
	@rm -f bootstrap tpp-${VER}-application-function.zip
	@(go build -ldflags '-s -w $(LDFLAGS)' -gcflags "all=-trimpath=$GOPATH" -o bootstrap && zip tpp-${VER}-application-function.zip bootstrap)

test:
	@(go test -v -coverprofile=coverage.out && go tool cover -func=coverage.out )

test-and-report:
	@(go test -v -coverprofile=coverage.out -json > report.json && go tool cover -func=coverage.out)
