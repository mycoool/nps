export GOPROXY=direct

sudo apt-get update
sudo apt-get install gcc-mingw-w64-i686 gcc-multilib
env GOOS=windows GOARCH=386 CGO_ENABLED=1 CC=i686-w64-mingw32-gcc go build -ldflags "-s -w -extldflags -static -extldflags -static" -buildmode=c-shared -o npc_sdk.dll cmd/sdk/sdk.go
env GOOS=linux GOARCH=386 CGO_ENABLED=1 CC=gcc go build -ldflags "-s -w -extldflags -static -extldflags -static" -buildmode=c-shared -o npc_sdk.so cmd/sdk/sdk.go
tar -czvf npc_sdk_old.tar.gz npc_sdk.dll npc_sdk.so npc_sdk.h

CGO_ENABLED=0 GOOS=windows GOARCH=386 go build -ldflags "-s -w -extldflags -static -extldflags -static" ./cmd/sdk/sdk.go

tar -czvf windows_386_client_old.tar.gz npc.exe conf/npc.conf conf/multi_account.conf


CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "-s -w -extldflags -static -extldflags -static" ./cmd/sdk/sdk.go

tar -czvf windows_amd64_client_old.tar.gz npc.exe conf/npc.conf conf/multi_account.conf


CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "-s -w -extldflags -static -extldflags -static" ./cmd/sdk/sdk.go

tar -czvf windows_amd64_server_old.tar.gz conf/nps.conf web/views web/static nps.exe


CGO_ENABLED=0 GOOS=windows GOARCH=386 go build -ldflags "-s -w -extldflags -static -extldflags -static" ./cmd/nps/nps.go

tar -czvf windows_386_server_old.tar.gz conf/nps.conf web/views web/static nps.exe