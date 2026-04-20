from Xlib import display, X
from Xlib.ext import xtest
import os, time

os.environ["DISPLAY"] = ":99"

left, top, cell = 236, 23, 119
moves = ["e2","e4","g1","f3","f1","c4","f3","g5","e4","d5","g5","f7"]

def coord(sq):
    f = "abcdefgh".index(sq[0])
    r = int(sq[1])
    x = int(left + f * cell + cell / 2)
    y = int(top + (8 - r) * cell + cell / 2)
    return x, y

d = display.Display()
for sq in moves:
    x, y = coord(sq)
    xtest.fake_input(d, X.MotionNotify, x=x, y=y)
    d.sync()
    time.sleep(0.1)
    xtest.fake_input(d, X.ButtonPress, 1)
    d.sync()
    time.sleep(0.05)
    xtest.fake_input(d, X.ButtonRelease, 1)
    d.sync()
    time.sleep(0.35)
