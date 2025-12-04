set GOOS=linux
set GOARCH=mipsle
set CGO_ENABLED=0
set GO111MODULE=on
set GOMIPS=softfloat

go build -ldflags "-s -w" -o luci-proxy github.com/unprintable123/go-auth-proxy

