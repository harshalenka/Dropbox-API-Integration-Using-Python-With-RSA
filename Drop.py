#!/usr/bin/env python
import os
import sys
import re
import dropbox
import tkinter as tk
from tkinter import filedialog
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto import Random
import random,string, sys, pkg_resources
import ntpath
import binascii
import base64

APP_Key=""
APP_Sec=""
ACK_TOK=""
status="no"
users={}
u=""
def randomString(N):
    return ''.join(random.choice(string.ascii_lowercase + ' '+string.ascii_uppercase+"0123456789") for i in range(N))
#Upload Section
def CR_Object(access):
    client = dropbox.client.DropboxClient(access)
    return client

def browse():
    root = tk.Tk()
    root.withdraw()
    file_path = filedialog.askopenfilename()
    return file_path

def file_name(path):
    head, tail = ntpath.split(path)
    return tail or ntpath.basename(head)

def client_det(client):
    print 'linked account: ', client.account_info()
    
def upload_f(client,destination="",pas="",suff=""):
    source=browse()
    f_name=file_name(source)
    F_next=os.path.splitext(source)[0]
    f = open(source, 'rb')
    if pas=="" and suff=="":
        destination=destination+"/"+f_name
        response = client.put_file(destination, f)
        print "Uploaded Successful\n"
    elif(pas!="" and suff!=""):
        destination=destination+"/"+pas+f_name+"_"+suff
        response = client.put_file(destination, f)
        print "Uploaded Successful\n"
    elif(pas!=""):
        destination=destination+"/"+pas+f_name
        response = client.put_file(destination, f)
        print "Uploaded Successful\n"
    elif(suff!=""):
        destination=destination+"/"+os.path.splitext(f_name)[0]+"_"+suff+os.path.splitext(f_name)[1]
        response = client.put_file(destination, f)
        print "Uploaded Successful\n"

def upload_b(client,Email,destination=""):
    f = open("C:\\Proj\\downloads\\"+Email+".txt", 'rb')
    destination=destination+"/"+Email+".txt"
    response = client.put_file(destination, f)
    print "Uploaded Successful\n"
    
#Group
def gp_upload(client,us):
    ch=raw_input("Do You Want To Upload(U) Or Download (D)?: ")       
    if(ch=="U"):
        username=raw_input("Enter Username of whom you want to send the file: ")
        Files= allfiles()
        encFiles=[Files]
        password = randomString(16)
        print "\n"
        for Tfiles in encFiles:
            if os.path.basename(Tfiles).startswith("(encrypted)"):
                print "%s is already encrypted" %str(Tfiles)
                pass
            elif Tfiles == os.path.join(os.getcwd(), sys.argv[0]):
                pass
            else:
                encrypt(SHA256.new(password).digest(), str(Tfiles))
                print "Done encrypting %s" %str(Tfiles)
        print "Select the encrypyted file you wat to upload:\n"
        upload_f(client,"/ACM Team Folder/"+username,"",us)
        print us
        print "Downloading Public Key of the user.........\n"
        download(client,"/ACM Team Folder/"+username+"/"+username+".txt",out_path="C:\\Proj\\downloads\\")
        fo=open('C:\\Proj\\downloads\\'+username +'.txt', "rb")
        out=fo.read()
        Obj = RSA.importKey(out)
        emsg = Obj.encrypt(password, 256)
        fo.close()
        Enc_pass=base64.b64encode(emsg[0])
        f_write(Enc_pass,"C:\\Proj\\downloads\\"+os.path.splitext(file_name(encFiles[0]))[0]+".txt")
        print "select the password file to upload...."
        upload_f(client,"/ACM Team Folder/"+username,"(encpassw)")
        os.remove("C:\\Proj\\downloads\\"+username+".txt")
    elif(ch=="D"):
        list_files(client,"/ACM Team Folder/"+us)
        sou=raw_input("Select the file you want to decrypt: ")
        print "\n"
        download(client,sou,out_path="C:\\Proj\\downloads\\")
        f_name=file_name(sou)
        if "(encrypted)" in f_name:
          out=os.path.splitext(file_name(f_name))[0].split("_")
          tmp_name="(encpassw)"+out[0].split("(encrypted)")[1]
          pw_name="/ACM Team Folder/"+us+"/"+tmp_name+".txt"
          download(client,pw_name,out_path="C:\\Proj\\downloads\\")
          st=f_read("C:\\Proj\\downloads\\"+tmp_name+".txt")
          st=base64.b64decode(st)
          priv=f_read("C:\\Proj\\"+"PUPR"+"_"+us+".txt")
          p=priv.split(":-:")[1]
          print "The Following is the password for the file Use Decrypt feature to decrypt the file:\n"  
          pasw= RSA_Dec(st,p)
          decrypt(SHA256.new(pasw).digest(),"C:\\Proj\\downloads\\"+f_name)
          print "File Decrypted at C:\\Poj\\downloads. \n"
          
        else:
            print "The file you selected is not encrypted.....\n"
def f_read(path):
    fo=open(path)
    str=fo.read()
    fo.close()
    return str
    
def list_files(client,fol="/"):
    folder_metadata = client.metadata(fol)
    for x in folder_metadata['contents']:
        if (x["is_dir"]==False):
            str= "{:50}  {:50}  {:50}".format(file_name(x["path"]),repr(x["is_dir"]),x["path"])+"\n"
            print str
        elif(x["is_dir"]==True):
            str= "{:50}  {:50}  {:50}".format(file_name(x["path"]),repr(x["is_dir"]),x["path"])+"\n"
            print str
            list_files(client,x["path"])
            
    print "\n"
    return
#Download Section
def download(client,path,out_path="C:\\Proj\\downloads\\"):
    f, metadata = client.get_file_and_metadata(path)
    if(metadata["is_dir"]==False):
        out_path=out_path+file_name(path)
        out = open(out_path, 'wb')
        out.write(f.read())
        out.close()
        print "Download Complete\n"
    else:
        print "Can't print a directory\n"
#Public Private Key
def RSA_gen(client,username,ps):
    random_generator = Random.new().read
    key = RSA.generate(2048, random_generator)
    PrivKey = key.exportKey("PEM")
    PubKey =  key.publickey().exportKey("PEM")
    print "Saving Public Private Keys\n"
    msg=username+":-:"+PrivKey+":-:"+PubKey
    fo = open("C:\\Proj\\PUPR"+"_"+username+".txt", "wb")
    fo.write(msg);
    fo.write("\n")
    fo.close()
    encrypt(SHA256.new(ps).digest(), "C:\\Proj\\PUPR"+"_"+username+".txt")
    source="C:\\Proj\\downloads\\(encrypted)PUPR"+"_"+username+".txt"
    f_name=file_name(source)
    f = open(source, 'rb')
    destination="/"+f_name
    response = client.put_file(destination, f)
    f.close()
    os.remove("C:\\Proj\\PUPR"+"_"+username+".txt")
    os.remove("C:\\Proj\\downloads\\(encrypted)PUPR"+"_"+username+".txt")
    return key,PrivKey,PubKey

def imp_RSA(client,username,ps):
    source="C:\\Proj\\(encrypted)PUPR"+"_"+username+".txt"
    download(client,"/(encrypted)PUPR"+"_"+username+".txt","C:\\Proj\\")
    decrypt(SHA256.new(ps).digest(), source)
    os.rename("C:\\Proj\\crypted)PUPR"+"_"+username+".txt", "C:\\Proj\\PUPR"+"_"+username+".txt")
    os.remove("C:\\Proj\\(encrypted)PUPR"+"_"+username+".txt")
    fo=open("C:\\Proj\\PUPR"+"_"+username+".txt", "rb")
    out=fo.read().split(":-:")
    if(out[0]==username):
        PrivKey=out[1]            
        PubKey=out[2]
    fo.close()
    return PrivKey,PubKey
def RSA_Enc(msg,PubKey):
    pubKeyObj = RSA.importKey(PubKey)
    emsg = pubKeyObj.encrypt(msg, 256)
    return emsg
    
def RSA_Dec(emsg,PrivKey):
    privKeyObj =  RSA.importKey(PrivKey)
    dmsg = privKeyObj.decrypt(emsg)
    return dmsg

#Encryption Decryption

def encrypt(key, filename):
        chunksize = 64 * 1024
        outFile = os.path.join("C:\\Proj\\downloads", "(encrypted)"+os.path.basename(filename))
        filesize = str(os.path.getsize(filename)).zfill(16)
        IV = ''
 
        for i in range(16):
                IV += chr(random.randint(0, 0xFF))
       
        encryptor = AES.new(key, AES.MODE_CBC, IV)
 
        with open(filename, "rb") as infile:
                with open(outFile, "wb") as outfile:
                        outfile.write(filesize)
                        outfile.write(IV)
                        while True:
                                chunk = infile.read(chunksize)
                               
                                if len(chunk) == 0:
                                        break
 
                                elif len(chunk) % 16 !=0:
                                        chunk += ' ' *  (16 - (len(chunk) % 16))
 
                                outfile.write(encryptor.encrypt(chunk))
 
 
def decrypt(key, filename):
        l = ['(encrypted)']
        outFile = os.path.join(os.path.dirname(filename), os.path.basename(filename[11:]))
        outFile=re.sub('|'.join(re.escape(r) for r in l), '', outFile)
        chunksize = 64 * 1024
        with open(filename, "rb") as infile:
                filesize = infile.read(16)
                IV = infile.read(16)
 
                decryptor = AES.new(key, AES.MODE_CBC, IV)
               
                with open(outFile, "wb") as outfile:
                        while True:
                                chunk = infile.read(chunksize)
                                if len(chunk) == 0:
                                        break
 
                                outfile.write(decryptor.decrypt(chunk))
 
                        outfile.truncate(int(filesize))
       
def allfiles():
        allFiles = []
        print "select files You Want to encrypt\n"
        source=browse()
        for root, subfiles, files in os.walk(source):
                for names in files:
                        allFiles.append(os.path.join(root, names))
        if (len(allFiles)==0):
                allFiles=source
 
        return allFiles

#Choice Section
def choice(client,usr,ps):
    cho="0"
    while (cho>="0" and cho<"9"):
        cho=raw_input("Enter Your Choice:")
        if cho=="1":
            list_files(client,fol="/")
            dst=raw_input("\nEnter Destination(for home directory pres enter.): ")
            print "\n"
            print "Input the file you want to upload:\n"
            upload_f(client,dst)
        elif cho=="2":
            print "{:50}  {:50}  {:50}".format("File","Is A Directory","File Path")
            list_files(client,fol="/")
            f_path=raw_input("Enter the path of the file you want to download: ")
            print "\n"
            download(client,f_path)
        elif cho=="3":
            print "{:50}  {:50}  {:50}".format("File","Is A Directory","File Path")
            list_files(client,"/")
        elif cho=="4":
            Files= allfiles()
            encFiles=[Files]
            password = raw_input("Enter the password: ")
            print "\n"
            for Tfiles in encFiles:
                if os.path.basename(Tfiles).startswith("(encrypted)"):
                    print "%s is already encrypted" %str(Tfiles)
                    pass
                elif Tfiles == os.path.join(os.getcwd(), sys.argv[0]):
                    pass
                else:
                    encrypt(SHA256.new(password).digest(), str(Tfiles))
                    print "Done encrypting %s" %str(Tfiles)
                    os.remove(Tfiles)
        elif cho=="5":
            print "Enter the File to decrypt:\n "
            file =browse()
            filename=file_name(file)
            password = raw_input("Enter the password: ")
            print "\n"
            if not os.path.exists(file):
                print "The file does not exist"
                sys.exit(0)
            elif not filename.startswith("(encrypted)"):
                print "%s is already not encrypted" %filename
                sys.exit()
            else:
                decrypt(SHA256.new(password).digest(), file)
                print "Done decrypting %s" %filename
                print "\n"
        elif cho=="6":
            gp_upload(client,usr)
        elif cho=="7":
            os.remove("C:\\Proj\\PUPR"+"_"+usr+".txt")
            sys.exit("Logged Out Successfully \n")
            

#signUP Section

def create_dir(newpath):
    if not os.path.exists(newpath):
        os.makedirs(newpath)
def create_f(newpath):
    fn = newpath
    try:
        file = open(fn, 'r')
    except IOError:
        file = open(fn, 'w')
def f_write(msg,dst):
    fo = open(dst, "ab")
    fo.write(msg);
    fo.write("\n")
    fo.close()

def SignUp():
    newpath = r'C:\Proj'
    file='C:\Proj\PWD.txt'
    Username=raw_input("Enter Username:")
    print "\n"
    print "Use only a password with atleast one small letter,one capital letter , one number and a symbol.\n"
    Password=raw_input("Enter Password:")
    print "\n"
    Email=raw_input("Enter Email:")
    print "\n"
    print "Creating Root Directory....\n"
    create_dir(newpath)
    create_dir("C:\Proj\downloads")
    print "Creating Files....\n"
    create_f(file)
    APP_Key=raw_input("Enter APP KEY..!!!: ")
    APP_Sec=raw_input("Enter APP SECERET..!!!: ")
    ACK_TOK=raw_input("Enter Access Token.!!!: ")
    client= CR_Object(ACK_TOK)
    key,PrivKey,PubKey=RSA_gen(client,Email,Password)
    path="C:\\Proj\\downloads\\"+Email+".txt"
    fo = open(path, "wb")
    msg=PubKey
    fo.write(msg)
    fo.write("\n")
    fo.close()
    upload_b(client,Email,"/ACM Team Folder/"+Email)
    print "\n Saving Your Data..."
    msg=Username+":"+Password+":"+Email+":"+APP_Key+":"+APP_Sec+":"+ACK_TOK
    f_write(msg,"C:\Proj\PWD.txt")
    print "\n Data Saved..."
    print "\n Pls Login To Continue.....\n"
    login(status)

#Login Section
def get_U_P():
    fo=open('C:\Proj\PWD.txt', "rb")
    for line in fo :
        out=line.strip().split(":")
        users[out[2]]=[out[0],out[1],out[3],out[4],out[5]]
    fo.close()
def validate(us,pw):
    if (us in users.keys()):
        if(users[us][1]==pw):
            return 1
        else:
            return 0
    else:
        return 0    
def em_eval(valid):
    if (re.match("[^@]+@[^@]+\.[^@]+", valid)):
        return 1
    else:
        return 0
def pw_eval(pwd):
    if (re.match(r'[A-Za-z0-9@#$%^&+=]{8,}', pwd)):
        return 1
    else:
        return 0
def login(status):
    get_U_P()
    if status=="no":
        u=raw_input("Enter Email: ")
        if(u!="" and em_eval(u)==1):
            p=raw_input("Enter Password: ")
            if(p!="" and pw_eval(p)==1):
                if(validate(u,p)==1):
                    status="yes"
                    APP_Key=users[u][2]
                    APP_Sec=users[u][3]
                    ACK_TOK=users[u][4]
                    client= CR_Object(ACK_TOK)
                    imp_RSA(client,u,p)
                    print "login Successful\n"
                    print "===========menu===========\n"
                    print "1.Upload File\n"
                    print "2.Download File\n"
                    print "3.List DropBox\n"
                    print "4.Encrypt File\n"
                    print "5.Decrypt File\n"
                    print "6.Group Upload\n"
                    print "7.Logout\n"
                    print "===========menu===========\n"
                    choice(client,u,p)
                else:
                    print "Username or Password Doesn't Match\n"
                    login(status)
            else:
                print "Password doesn't match the rules"
                login(status)
        else:
            print "Wrong Password"+"\n"
            login(status)
    else:
        client= CR_Object(ACK_TOK)
        imp_RSA(client,u,p)
        print "You Are Already logged In\n"
        print "===========menu===========\n"
        print "1.Upload File\n"
        print "2.Download File\n"
        print "3.List DropBox\n"
        print "4.Encrypt File\n"
        print "5.Decrypt File\n"
        print "6.Group Upload\n"
        print "7.Logout\n"
        print "===========menu===========\n"
        choice(client,u,p)

choe=raw_input("What Do You Want TO Do Sign Up ('S') or Login('L'): ")
if choe=="S":
    SignUp()
elif choe=="L":
    login(status)
