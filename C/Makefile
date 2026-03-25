CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c11
LDFLAGS = -lcrypto -lsqlite3

all: password_manager

password_manager: password_manager.c
	$(CC) $(CFLAGS) -o password_manager password_manager.c $(LDFLAGS)

gui: gui/password_manager_gui.c
	$(CC) $(CFLAGS) -o gui/password_manager_gui gui/password_manager_gui.c \
		$(LDFLAGS) \
		-I/usr/include/gtk-3.0 -I/usr/include/pango-1.0 -I/usr/include/glib-2.0 \
		-I/usr/include/harfbuzz -I/usr/include/cairo \
		-I/usr/include/gdk-pixbuf-2.0 -I/usr/include/atk-1.0 \
		-I/usr/lib/aarch64-linux-gnu/glib-2.0/include \
		-lgtk-3 -lgdk-3 -lpangocairo-1.0 -lpango-1.0 -lharfbuzz \
		-latk-1.0 -lcairo-gobject -lcairo -lgdk_pixbuf-2.0 -lgio-2.0 \
		-lgobject-2.0 -lglib-2.0

clean:
	rm -f password_manager passwords.db
	rm -f gui/password_manager_gui

test: password_manager
	rm -f passwords.db
	echo "testpass" | ./password_manager --init
	echo "testpass" | ./password_manager --add github.com testuser secret123
	echo "testpass" | ./password_manager --get github.com
	echo "testpass" | ./password_manager --list

.PHONY: all clean test gui
