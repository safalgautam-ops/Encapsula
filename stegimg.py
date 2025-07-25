from PIL import Image

def genData(data):
    return [format(ord(char), '08b') for char in data]

def modPix(pix, data):
    datalist = genData(data)  # List of binary strings for each char
    lendata = len(datalist)
    imdata = iter(pix)        # Iterator over pixels

    for i in range(lendata):
        # Take 3 pixels (9 RGB values) at a time
        pixels = [value for value in next(imdata)[:3] + next(imdata)[:3] + next(imdata)[:3]]

        # Modify first 8 pixel values according to binary bits
        for j in range(8):
            bit = datalist[i][j]
            original_val = pixels[j]

            if bit == '0':
                # If bit is 0, pixel value should be even
                if pixels[j] % 2 != 0:  # If odd, subtract 1 to make even
                    pixels[j] -= 1
            else:
                # If bit is 1, pixel value should be odd
                if pixels[j] % 2 == 0:  # If even, adjust by +1 or -1 to make odd
                    # Avoid going below 0
                    if pixels[j] == 0:
                        pixels[j] += 1
                    else:
                        pixels[j] -= 1

        # Set the 9th pixel value as flag:
        # Odd if last character (stop), even if more data follows
        if i == lendata - 1:
            # Make odd (stop flag)
            if pixels[-1] % 2 == 0:
                if pixels[-1] == 0:
                    pixels[-1] += 1 #  
                else:
                    pixels[-1] -= 1
        else:
            # Make even (continue flag)
            if pixels[-1] % 2 != 0:
                pixels[-1] -= 1 #

        # Yield modified pixels as tuples of 3 RGB values
        yield tuple(pixels[0:3]) 
        yield tuple(pixels[3:6])
        yield tuple(pixels[6:9])

def encode_enc(newimg, data):
    w = newimg.size[0]
    (x, y) = (0, 0)

    for pixel in modPix(newimg.getdata(), data):
        newimg.putpixel((x, y), pixel)
        x = 0 if x == w - 1 else x + 1
        y += 1 if x == 0 else 0

def encode(img_path, data, out_path):
    image = Image.open(img_path, 'r')
    if image.mode != 'RGB':
        print("[!] Image mode must be RGB.")
    if not data:
        raise ValueError("Data is empty.")
    if not out_path:
        raise ValueError("Output image path is required.")
    newimg = image.copy()
    encode_enc(newimg, data)
    newimg.save(out_path, out_path.split(".")[-1].upper())
    return "file saved successfully."

def decode(img):
    image = Image.open(img, 'r')
    imgdata = iter(image.getdata())
    data = ""

    while True:
        # Read 3 pixels (9 RGB values)
        pixels = [value for value in next(imgdata)[:3] + next(imgdata)[:3] + next(imgdata)[:3]]

        # Extract first 8 bits from pixel parity (odd=1, even=0)
        binstr = ''.join(['1' if val % 2 != 0 else '0' for val in pixels[:8]])

        # Convert binary string to character
        data += chr(int(binstr, 2))

        # If 9th pixel is odd, stop decoding
        if pixels[-1] % 2 != 0:
            break

    return data
