# nimrm build system

BIN     = nimrm
SRC     = nimrm.nim
VERSION = 1.0.0
DEB     = $(BIN)_$(VERSION)_amd64.deb
DEBDIR  = build/deb/$(BIN)
NIMC    = nim
FLAGS   = -d:release -d:ssl --threads:on --opt:speed
MINGW64 = x86_64-w64-mingw32-gcc

.PHONY: all linux windows ssl deb clean

all: linux

linux:
	$(NIMC) c $(FLAGS) --nimcache:nimcache/linux -o:$(BIN) $(SRC)
	@echo "[+] Built: ./$(BIN)"

ssl:
	$(NIMC) c $(FLAGS) --nimcache:nimcache/linux-ssl -o:$(BIN)-ssl $(SRC)
	@echo "[+] Built: ./$(BIN)-ssl"

windows:
	$(NIMC) c $(FLAGS) --nimcache:nimcache/windows --os:windows --cpu:amd64 --cc:gcc --gcc.exe:$(MINGW64) --gcc.linkerexe:$(MINGW64) -o:$(BIN).exe $(SRC)
	@echo "[+] Built: ./$(BIN).exe"

windows-ssl:
	$(NIMC) c $(FLAGS) --nimcache:nimcache/windows-ssl --os:windows --cpu:amd64 --cc:gcc --gcc.exe:$(MINGW64) --gcc.linkerexe:$(MINGW64) -o:$(BIN)-ssl.exe $(SRC)
	@echo "[+] Built: ./$(BIN)-ssl.exe"

deb: linux
	rm -rf $(DEBDIR)
	mkdir -p $(DEBDIR)/DEBIAN $(DEBDIR)/usr/bin $(DEBDIR)/usr/share/doc/$(BIN)
	install -m 0755 $(BIN) $(DEBDIR)/usr/bin/$(BIN)
	install -m 0644 README.md LICENSE $(DEBDIR)/usr/share/doc/$(BIN)/
	printf '%s\n' \
		'Package: $(BIN)' \
		'Version: $(VERSION)' \
		'Section: net' \
		'Priority: optional' \
		'Architecture: amd64' \
		'Maintainer: Chokri Hammedi (blue0x1)' \
		'Depends: libc6, libkrb5-3, libssl3' \
		'Homepage: https://github.com/blue0x1/nimrm' \
		'Description: Native Nim WinRM shell client' \
		' nimrm is a native WinRM shell client with NTLM, Kerberos,' \
		' file transfer, in-memory helpers, and AD/OPSEC reporting.' \
		> $(DEBDIR)/DEBIAN/control
	printf '%s\n' \
		'$(BIN) ($(VERSION)) stable; urgency=medium' \
		'' \
		'  * Initial public release.' \
		'' \
		' -- Chokri Hammedi (blue0x1)  Thu, 30 Apr 2026 00:00:00 +0000' \
		> $(DEBDIR)/usr/share/doc/$(BIN)/changelog.Debian
	gzip -9 $(DEBDIR)/usr/share/doc/$(BIN)/changelog.Debian
	printf '%s\n' \
		'Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/' \
		'Upstream-Name: nimrm' \
		'Source: https://github.com/blue0x1/nimrm' \
		'' \
		'Files: *' \
		'Copyright: 2026 Chokri Hammedi (blue0x1)' \
		'License: MIT' \
		' See /usr/share/doc/nimrm/LICENSE for the full license text.' \
		> $(DEBDIR)/usr/share/doc/$(BIN)/copyright
	chmod 0644 $(DEBDIR)/usr/share/doc/$(BIN)/changelog.Debian.gz $(DEBDIR)/usr/share/doc/$(BIN)/copyright
	dpkg-deb --root-owner-group --build $(DEBDIR) $(DEB)
	@echo "[+] Built: ./$(DEB)"

clean:
	rm -f $(BIN) $(BIN)-ssl $(BIN).exe $(BIN)-ssl.exe $(DEB)
	rm -rf nimcache build
