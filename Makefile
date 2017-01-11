NAME=blocklist
VERSION=1.1.1

SBIN_FILES=blocklist.pl
ETC_FILES=blacklist whitelist

PKG_DIR=pkg
PKG_NAME=$(NAME)-$(VERSION)
PKG=$(PKG_DIR)/$(PKG_NAME).tar.gz
SIG=$(PKG_DIR)/$(PKG_NAME).asc

PREFIX?=/
SBIN_DIR=$(PREFIX)/sbin/
ETC_DIR=$(PREFIX)/etc/$(NAME)

pkg:
	mkdir -p $(PKG_DIR)

$(PKG): pkg
	git archive --output=$(PKG) --prefix=$(PKG_NAME)/ HEAD

build: $(PKG)

$(SIG): $(PKG)
	gpg --sign --detach-sign --armor $(PKG)

sign: $(SIG)

clean:
	rm -f $(PKG) $(SIG)

all: $(PKG) $(SIG)

test:

tag:
	git tag v$(VERSION)
	git push --tags

release: $(PKG) $(SIG) tag

install:
	mkdir -p $(SBIN_DIR)
	cp -r $(SBIN_FILES) $(SBIN_DIR)/
	mkdir -p $(ETC_DIR)
	cp -r $(ETC_FILES) $(ETC_DIR)/

uninstall:
	rm -f $(SBIN_DIR)/$(SBIN_FILES)
	rm -rf $(ETC_DIR)


.PHONY: build sign clean test tag release install uninstall all
