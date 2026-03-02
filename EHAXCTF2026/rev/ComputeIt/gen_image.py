from PIL import Image
rows = '''






         #### #  # #  # #  #   ## ###  #### #   # ###  ##  ###       #   # #  # ####       ####   #  #### #  # ###   ##
         #    #  # #  #  ##   ##  #  #    # #   #  #  #  # #  #      #   # #  # #          #  #  ##  #    #  #  #   ##
         ###  #### ####   #   #   #  #  ### # # #  #  #  # #  # #### # # # #### ###  ####  ###    #  # ## ####  #   #
         #    #  #    #  ##   ##  #  #    # ## ##  #  #  # #  #      ## ##    #    #       # #    #  #  # #  #  #   ##
         #### #  #    # #  #   ## #  # #### #   #  #   ##  #  #      #   #    # ####       #  # #### #### #  #  #    ##







'''

lines = rows.splitlines()
band = [l.rstrip("\n") for l in lines if "#" in l]   # gets the 7 bitmap rows

W = max(len(l) for l in band)
H = len(band)

# pad to equal width
band = [l.ljust(W) for l in band]

sx, sy = 12, 28
img = Image.new("L", (W*sx, H*sy), 255)

for y, line in enumerate(band):
    for x, ch in enumerate(line):
        if ch == "#":
            for yy in range(y*sy, (y+1)*sy):
                for xx in range(x*sx, (x+1)*sx):
                    img.putpixel((xx, yy), 0)

img.save("flag_band.png")
print("saved flag_band.png")