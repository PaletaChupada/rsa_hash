# Importado de librerias
from hashlib import sha1
from multiprocessing.sharedctypes import Value
import ntpath
from tkinter import *
from tkinter import filedialog
from tkinter import messagebox
import tkinter as tk
import functools
import numpy as np
from Crypto.Hash import SHA1
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.PublicKey import RSA

# Funcion para abrir el explorador y guardar la ruta
def browseFiles(): 
    ruta = filedialog.askopenfilename(initialdir = "D:/", title = "Select a File", filetypes = (("Text files", "*.txt*"), ("all files", "*.*")))
    labelInfo = Label(principal, text="Ruta del archivo: ")
    labelInfo.place(x=150,y=0) 
    labelExplorador.configure(text=ruta)

def secundaria_v(master,  callback=None, args=(), kwargs={}):    
    def browseFilesPriv(): 
        rutaPriv = filedialog.askopenfilename(initialdir = "D:/", title = "Select a File", filetypes = (("Llave", "*.pem*"), ("all files", "*.*")))
        labelInfoF = Label(main_frame, text="Ruta del archivo: ")
        labelInfoF.place(x=150,y=0) 
        labelClavePriv.configure(text=rutaPriv)

    def firmar():
        ruta = labelExplorador.cget("text") # Obtenemos la direccion del archivo
        nombre = str(ntpath.basename(ruta)) # Obtenemos su nombre
        ruta_aux = str(ruta).replace(nombre,"") # Eliminamos el nombre de la ruta
        nombre = nombre.replace(".txt","") # Eliminamos su extension del nombre
        
        # Abrimos el archivo de texto
        f = open(ruta,"rb")
        cadena_by = f.read()
        f.close()

        # Obtenemos las llaves a traves del .pem y las convertimos a bytes
        rutaK_Priv = labelClavePriv.cget("text")
        
        f = open(rutaK_Priv,"rb")
        kpriv = RSA.import_key(f.read())
        h = SHA1.new()
        h.update(cadena_by)
        
        signer = PKCS115_SigScheme(kpriv)
        signature = signer.sign(h)

        # Escribimos el archivo firmado
        f = open(ruta_aux+nombre+"_F.txt","wb")
        f.write(cadena_by)
        f.write(b'\n\nFirma{\n')
        f.close()
        f = open(ruta_aux+nombre+"_F.txt","ab")
        f.write(signature)
        f.close()
        
        messagebox.showinfo(message="Archivo Firmado", title="Firma exitosa")
        print("Archivo firmado")
        

    # Creamos interfaz para que el usario ingrese la clave
    if callback is not None:
        callback = functools.partial(callback, *args, **kwargs)

    main_frame = tk.Frame(master)
    labelEspacio3 = Label(main_frame, text="")
    labelClavePriv = Label(main_frame, text="Selecciona la llave privada", height=4)
    buttonBuscarPriv = Button(main_frame, text = "Buscar llave privada", command = browseFilesPriv)
    buttonFirmar = Button(main_frame, text="Firmar", command = firmar)
    buttonRegresar = Button(main_frame, text = "Regresar", command = callback)
    labelClavePriv.pack()
    buttonBuscarPriv.pack()
    labelEspacio3.pack()
    buttonFirmar.pack()
    buttonRegresar.pack()

    return main_frame

def tercera_v(master,  callback=None, args=(), kwargs={}):

    def browseFilesPub(): 
        rutaPub = filedialog.askopenfilename(initialdir = "D:/", title = "Select a File", filetypes = (("Llave", "*.pem*"), ("all files", "*.*")))
        labelInfoF = Label(main_frame, text="Ruta del archivo: ")
        labelInfoF.place(x=150,y=0) 
        labelClavePub.configure(text=rutaPub)
    
    def verificar():
        # Obtenemos el valor de la firma y del mensaje
        ruta = labelExplorador.cget("text") # Obtenemos la direccion del archivo
        aux = []
        with open(ruta,"rb") as f:
            for linea in f:
                aux.append(linea)
                if(linea == b'Firma{\n'):
                    sign = f.read()
                    break

        # Obtenemos el mensaje para aplicar el hash
        cadena = b''
        for n in range(len(aux)-2):
            cadena += aux[n]
        cadena = cadena[:-1]

        # Obtenemos las claves a patir del los .txt y las convertimos a bytes
        rutaK_Pub = labelClavePub.cget("text")
        
        # Obtenemos la llave publica
        f = open(rutaK_Pub,'rb')
        kpub = RSA.import_key(f.read())

        # Aplicamos el hash al mensaje
        h = SHA1.new()
        h.update(cadena)

        # Verificamos la firma
        signer = PKCS115_SigScheme(kpub)
        try:
            signer.verify(h,sign)
            messagebox.showinfo(message="Verificacion exitosa", title="Firma valida")
            print("Firma valida")
        except (ValueError, TypeError):
            messagebox.showinfo(message="Llave o mensaje erroneos", title="Firma invalida")
            print("Firma no valida")


    # Creamos interfaz para que el usario ingrese la clave
    if callback is not None:
        callback = functools.partial(callback, *args, **kwargs)

    main_frame = tk.Frame(master)
    labelEspacio3 = Label(main_frame, text="")
    labelClavePub = Label(main_frame, text="Selecciona la llave publica", height=4)
    buttonBuscarPub = Button(main_frame, text = "Buscar llave publica", command = browseFilesPub)
    buttonVerificar = Button(main_frame, text="Verificar", command = verificar)
    buttonRegresar = Button(main_frame, text = "Regresar", command = callback)
    labelClavePub.pack()
    buttonBuscarPub.pack()
    labelEspacio3.pack()
    buttonVerificar.pack()
    buttonRegresar.pack()

    return main_frame

def mostrar_prin():
    secundaria.pack_forget()
    tercera.pack_forget()
    principal.pack(side="top", fill="both", expand=True)

def mostrar_sec():
    principal.pack_forget()
    secundaria.pack(side="top", fill="both", expand=True)

def mostrar_ter():
    principal.pack_forget()
    tercera.pack(side="top", fill="both", expand=True)

# Creacion de la ventana y anexo de los botones y los labels                                                                                                       
root = tk.Tk() 
root.title('Practica 2 (Firma con RSA y SHA1)') 
root.geometry("400x300")
root.resizable(0,0)
principal = tk.Frame(root)
labelEspacio = Label(principal, text="")
labelEspacio2 = Label(principal, text="")
labelExplorador = Label(principal, text = "Selecciona un archivo txt", height=4)    
buttonBuscar = Button(principal, text = "Buscar", command = browseFiles)
buttonCifrar = Button(principal, text = "Firmar", command=mostrar_sec)
buttonValidar = Button(principal, text = "Validar", command=mostrar_ter)  
buttonSalir = Button(principal, text = "Salir", command = exit)  
labelExplorador.pack()
buttonBuscar.pack()
labelEspacio.pack()
buttonCifrar.pack()
buttonValidar.pack()
labelEspacio2.pack()
buttonSalir.pack()
secundaria = secundaria_v(root, mostrar_prin)
tercera = tercera_v(root, mostrar_prin)
mostrar_prin()
root.mainloop() 