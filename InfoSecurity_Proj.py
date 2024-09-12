""" 
    Arian Asgarnezhad Tabrizi 
    information security project (by Dr.Hamidzadeh)
    
"""

import secrets
import string
from functools import reduce
from Crypto.Cipher import AES 
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter
from PIL import Image 
import operator
import sys


filename = "F:\PRG-Projects\PRG Projects\security project\QuantimBreakButterfly.bmp"
filename_out_en = "F:\PRG-Projects\PRG Projects\security project\\" 
filename_out_de = "F:\PRG-Projects\PRG Projects\security project\\" 
format = "BMP" 

# Generate Random 16 byte Key
key = ''.join(secrets.choice(string.ascii_uppercase + string.ascii_lowercase) for i in range(16)) 

# Generate 16 byte counter for CTR mode
ctr = Counter.new(128) 


def convert_to_RGB(data): 
    """
        Maps the RGB 
        
    """
    r, g, b = tuple(map(lambda d: [data[i] for i in range(0,len(data)) if i % 3 == d], [0, 1, 2])) 
    pixels = tuple(zip(r,g,b)) 
    return pixels 


def process_image(filename): 
    """
        process en/decrypted image
        
    """
    # Opens image and converts it to RGB format for PIL 
    im_src = Image.open(filename) 
    im_size = im_src.size
    
    data = im_src.convert("RGB").tobytes()  
 
    # Since we will pad the data to satisfy AES's multiple-of-16 requirement, we will store the original data length and "unpad" it later. 
    original = len(data)  
    
    ecb_enc_show(data,original,im_size).show()
    ecb_dec_show(original,ecb_enc_show(data,original,im_size)).show()
    
    cbc_enc_show(data,original,im_size).show()
    cbc_dec_show(original,cbc_enc_show(data,original,im_size)).show()
    
    ctr_enc_show(data,original,im_size).show()
    ctr_dec_show(original,ctr_enc_show(data,original,im_size)).show()
      

# CBC Enc
def aes_cbc_encrypt(key, data, mode=AES.MODE_CBC): 
    # set the initialization vector
    IV = ''.join(secrets.choice(string.ascii_uppercase + string.ascii_lowercase) for i in range(16)) 
    aes = AES.new(key.encode('utf8'), mode, IV=IV.encode('utf8')) 
    new_data = aes.encrypt(data) 
    return new_data 
# CBC Dec
def aes_cbc_decrypt(key, data, mode=AES.MODE_CBC): 
    # set the initialization vector 
    IV = ''.join(secrets.choice(string.ascii_uppercase + string.ascii_lowercase) for i in range(16)) 
    aes = AES.new(key.encode('utf8'), mode, IV=IV.encode('utf8')) 
    new_data = aes.decrypt(data) 
    return new_data 

# ECB Enc
def aes_ecb_encrypt(key, data, mode=AES.MODE_ECB): 
    aes = AES.new(key.encode('utf8'), mode) 
    new_data = aes.encrypt(data) 
    return new_data 
# ECB Dec
def aes_ecb_decrypt(key, data, mode=AES.MODE_ECB): 
    aes = AES.new(key.encode('utf8'), mode) 
    new_data = aes.decrypt(data) 
    return new_data 


# CTR Enc
def aes_ctr_encrypt(key, data, mode=AES.MODE_CTR   ): 
    aes = AES.new(key.encode('utf8'), mode , counter=ctr   )      
    new_data = aes.encrypt(data) 
    return new_data 

# CTR Dec
def aes_ctr_decrypt(key, data, mode=AES.MODE_CTR   ): 
    aes = AES.new(key.encode('utf8'), mode , counter=ctr  )  
    new_data = aes.decrypt(data) 
    return new_data  


# ECB show
def ecb_enc_show(data,original,im_size ):
    new_ecb = convert_to_RGB(aes_ecb_encrypt(key, pad(data,16))[:original])  
    im_ecb = Image.new('RGB', im_size) 
    im_ecb.putdata(list(new_ecb) , scale=1 ) 
    im_ecb.save(filename_out_en+"ecb_en."+format, format) 
    return im_ecb

def ecb_dec_show(original,im_ecb):
    data_d = im_ecb.convert("RGB").tobytes()
    new_ecb_d = convert_to_RGB(aes_ecb_decrypt(key, pad(data_d,16))[:original])  
    im_ecb_d = Image.new('RGB', im_ecb.size ) 
    im_ecb_d.putdata(list(new_ecb_d) , scale=1 )
    im_ecb_d.save(filename_out_de+"ecb_de."+format, format) 
    return im_ecb_d
    
# CBC show    
def cbc_enc_show(data,original,im_size):
    new_cbc = convert_to_RGB(aes_cbc_encrypt(key, pad(data,16))[:original])  
    im_cbc = Image.new('RGB', im_size)
    im_cbc.putdata(list(new_cbc) , scale=1 )
    im_cbc.save(filename_out_en+"cbc_en."+format, format)  
    return im_cbc

def cbc_dec_show(original,im_cbc): 
    data_d = im_cbc.convert("RGB").tobytes()
    new_cbc_d = convert_to_RGB(aes_cbc_decrypt(key, pad(data_d, 16) )[:original]) 
    im_cbc_d = Image.new('RGB', im_cbc.size) 
    im_cbc_d.putdata(list(new_cbc_d) , scale=1 )  
    im_cbc_d.save(filename_out_de+"cbc_de."+format, format)  
    return im_cbc_d
    
# CTR show
def ctr_enc_show(data,original,im_size):
    new_ctr = convert_to_RGB(aes_ctr_encrypt(key, data )[:original])  
    im_ctr = Image.new('RGB', im_size) 
    im_ctr.putdata(list(new_ctr) , scale=1 ) 
    im_ctr.save(filename_out_en+"ctr_en."+format, format)  
    return im_ctr

def ctr_dec_show(original,im_ctr): 
    data_d = im_ctr.convert("RGB").tobytes() 
    new_ctr_d = convert_to_RGB(aes_ctr_decrypt(key, data_d )[:original]) 
    im_ctr_d = Image.new('RGB', im_ctr.size) 
    im_ctr_d.putdata(list(new_ctr_d) , scale=1 )  
    im_ctr_d.save(filename_out_de+"ctr_de."+format, format)
    return im_ctr_d


# Main   
if __name__ == '__main__' :
    process_image(filename) 