#!/usr/bin/env python3
"""dragsource.py FILE... - a window with a button that drags the files as text/uri-list."""
import sys
import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, Gdk, GLib

uris = [GLib.filename_to_uri(p, None) for p in sys.argv[1:]]
win = Gtk.Window(title="dragsource")
win.move(900, 700)  # without a window manager this is only a hint
btn = Gtk.Button(label="DRAG ME")
btn.drag_source_set(Gdk.ModifierType.BUTTON1_MASK, [Gtk.TargetEntry.new("text/uri-list", 0, 1)], Gdk.DragAction.COPY)
btn.connect("drag-data-get", lambda w, ctx, data, info, t: data.set_uris(uris))
win.add(btn)
win.connect("destroy", Gtk.main_quit)
win.show_all()
Gtk.main()
