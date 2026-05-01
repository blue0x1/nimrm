# nimrm build system

BIN     = nimrm
SRC     = nimrm.nim
NIMC    = nim
FLAGS   = -d:release --opt:speed --nimcache:nimcache
MINGW64 = x86_64-w64-mingw32-gcc

.PHONY: all linux windows ssl clean

all: linux

linux:
	$(NIMC) c $(FLAGS) -o:$(BIN) $(SRC)
	@echo "[+] Built: ./$(BIN)"

ssl:
	$(NIMC) c $(FLAGS) -d:ssl -o:$(BIN)-ssl $(SRC)
	@echo "[+] Built: ./$(BIN)-ssl"

windows:
	$(NIMC) c $(FLAGS) --os:windows --cpu:amd64 --cc:gcc --gcc.exe:$(MINGW64) --gcc.linkerexe:$(MINGW64) -o:$(BIN).exe $(SRC)
	@echo "[+] Built: ./$(BIN).exe"

windows-ssl:
	$(NIMC) c $(FLAGS) -d:ssl --os:windows --cpu:amd64 --cc:gcc --gcc.exe:$(MINGW64) --gcc.linkerexe:$(MINGW64) -o:$(BIN)-ssl.exe $(SRC)
	@echo "[+] Built: ./$(BIN)-ssl.exe"

clean:
	rm -f $(BIN) $(BIN)-ssl $(BIN).exe $(BIN)-ssl.exe
	rm -rf nimcache
