import math

THRESH = 1e-9
EPS = 1e-6
MAX_NONCONV = 0x31  # matches the binary's loop limit logic

def steps_to_root1(x0, y0):
    x = float(x0)
    y = float(y0)
    steps = 0
    nonconv = 0

    while nonconv <= MAX_NONCONV:
        # f(z)=z^3-1, with z=x+iy
        a = x*x*x - 3.0*x*y*y - 1.0          # Re(f)
        b = 3.0*x*x*y - y*y*y                # Im(f)

        # f'(z)=3z^2
        c = 3.0*(x*x - y*y)                  # Re(f')
        d = 6.0*x*y                          # Im(f')

        den = c*c + d*d                      # |f'|^2
        if THRESH > den:
            break

        # (a+ib)/(c+id)
        dx = (a*c + b*d) / den
        dy = (b*c - a*d) / den

        x -= dx
        y -= dy
        steps += 1

        if abs(x - 1.0) < EPS and abs(y) < EPS:
            break

        nonconv += 1

    return steps

# load points
pts = []
with open("signal_data.txt","r") as f:
    for line in f:
        line=line.strip()
        if not line: 
            continue
        xr, yi = line.split(",")
        pts.append((float(xr), float(yi)))

assert len(pts) == 2600

# compute bitmap: 1 if "accepted" (exactly 12 steps)
bits = [1 if steps_to_root1(x,y)==12 else 0 for x,y in pts]

# reshape to 100x26 and print as ASCII art
W, H = 130, 20
for r in range(H):
    row = bits[r*W:(r+1)*W]
    print("".join("#" if v else " " for v in row))