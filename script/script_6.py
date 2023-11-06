import os
import glob
from PIL import Image
from pyzbar.pyzbar import decode

# Replace 'path/to/folder' with the actual path to the folder containing the QR codes
folder_path = 'qrcodes/'
output_file = 'qr_codes.txt'

# Create a list of all the image files in the folder
image_files = glob.glob(os.path.join(folder_path, '*.jpg'))

# Open the output file for writing
with open(output_file, 'w') as f:
    # Loop over each image file in the folder
    for image_file in image_files:
        # Open the image and decode the QR code
        image = Image.open(image_file)
        qr_code = decode(image)

        # If a QR code was detected, write the URL to the output file
        if qr_code:
            url = qr_code[0].data.decode()
            f.write(url + '\n')