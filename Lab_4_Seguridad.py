'''Lab 4 Seguridad Informatica (Lab 6 Evaluado)
Integrantes: Cristian Madariaga, Christian De Jesus
Ayudante: Manuel Fuentes
Profesor: Manuel Alba
Fecha de entrega: sábado 19 de noviembre, 2022
IMPORTANTE: SE REQUIERE LIBRERIA RSA
INSTALAR CON COMANDO ==> pip install rsa
'''
# -------------------------------------------------------------------------- #
#                                Importaciones                               #
# -------------------------------------------------------------------------- #
import random
from math import pow
from time import sleep
from distutils.cmd import Command
from platform import java_ver
from select import select
import tkinter as tk
from tkinter.tix import Select
from tkinter import END, INSERT, filedialog
import rsa

# -------------------------------------------------------------------------- #
#                                  ElGamal                                   #
# -------------------------------------------------------------------------- #
#!Hacer ElGamal
#*p = Primo aleatorio
#*g = Generador aleatorio
#*a = Clave privada emisor
#*b = Clave privada receptor

a = random.randint(2, 10)

#!Maximo comun divisor
def gcd(a, b):
	if a < b:
		return gcd(b, a)
	elif a % b == 0:
		return b;
	else:
		return gcd(b, a % b)

#!Generador de llaves aleatorias
def gen_key(q):

	key = random.randint(pow(10, 20), q)
	while gcd(q, key) != 1:
		key = random.randint(pow(10, 20), q)

	return key

#!Exponencial modular
def power(a, b, c):
	x = 1
	y = a

	while b > 0:
		if b % 2 != 0:
			x = (x * y) % c;
		y = (y * y) % c
		b = int(b / 2)

	return x % c

#!Encriptacion
def gamal_encrypt(msg, q, h, g):

	en_msg = []

	k = gen_key(q)
	s = power(h, k, q)
	p = power(g, k, q)
	
	for i in range(0, len(msg)):
		en_msg.append(msg[i])

	print("g^k used : ", p)
	print("g^ak used : ", s)
	for i in range(0, len(en_msg)):
		en_msg[i] = s * ord(en_msg[i])

	return en_msg, p

#!Decriptacion
def gamal_decrypt(en_msg, p, key, q):

	dr_msg = []
	h = power(p, key, q)
	for i in range(0, len(en_msg)):
		dr_msg.append(chr(int(en_msg[i]/h)))
		
	return dr_msg

def elgamal(msg):
    q = random.randint(pow(10, 20), pow(10, 50))
    g = random.randint(2, q)
    
    key = gen_key(q)
    h = power(g, key, q)
    
    en_msg, p = gamal_encrypt(msg, q, h, g)
    dr_msg = gamal_decrypt(en_msg, p, key, q)
    dmsg = ''.join(dr_msg)
    
    return en_msg, dmsg
# -------------------------------------------------------------------------- #
#                                 RSA                                        #
# -------------------------------------------------------------------------- #
#!Hacer RSA
#*p = Primer numero privado
#*q = Segundo numero privado
#*e = Exponente publico
#*b = Exponente privado

#!Generador de proceso
(publicKey, privateKey) = rsa.newkeys(1024)

#!Verificación firma
def verify(msg, sign, key):
    try:
        return rsa.verify(msg.encode('ascii'), sign, key,) == 'SHA-1'
    except:
        return False

#!Proceso RSA
def RSA(msg, pukey, prkey):
    en_msg = rsa.encrypt(msg.encode('ascii'), pukey)
    text.insert(INSERT,'Mensaje encriptado con RSA exitosamente\n')
    sign = rsa.sign(msg.encode('ascii'), prkey, 'SHA-1')
    text.insert(INSERT,'Su firma RSA es: '+str(sign)+'\n')
    dr_msg = rsa.decrypt(en_msg, prkey).decode('ascii')
    if verify(dr_msg, sign, pukey):
        text.insert(INSERT,'Mensaje verificado con firma\n')
    else:
        text.insert(INSERT,'No se pudo verificar mensaje\n')
    return en_msg, dr_msg

# -------------------------------------------------------------------------- #
#                           Funciones varias                                 #
# -------------------------------------------------------------------------- #
#!Función para obtener archivo
def GetFile():
    file_path = filedialog.askopenfilename(title = "Seleccione archivo de entrada",
                                                filetypes=[("Archivo de Texto","*.txt")])
    return file_path
# -------------------------------------------------------------------------- #
#                                  Cifrado                                   #
# -------------------------------------------------------------------------- #
#!Encriptacion segun opcion escogida
def encrypt():
    text.delete(1.0, END)
    path = GetFile()
    #!Seleccion 1 --> ElGamal
    if path != '' and var.get()==1:
        with open(path) as opened_file:
            content = opened_file.read()
            encriptado, decriptado = elgamal(content)
            text.insert(INSERT,'Mensaje encriptado con ElGamal exitosamente\n')
            text.insert(INSERT,'\nSu mensaje cifrado es: '+str(encriptado)+'\n')
            text.insert(INSERT,'\nDescifrando mensaje...\n')
            #!Proceso de descifrado
            with open('MensajeRecibido.txt', 'w') as salida:
                salida.write(decriptado)
                text.insert(INSERT,'\nMensaje descifrado y guardado en MensajeRecibido.txt\n')
    #!Seleccion 2 --> RSA
    elif path != '' and var.get()==2:
        with open(path) as opened_file:
            content = opened_file.read()
            encriptado, decriptado = RSA(content, publicKey, privateKey)
            text.insert(INSERT,'\nSu mensaje cifrado es: '+str(encriptado)+'\n')
            text.insert(INSERT,'\nDescifrando mensaje...\n')
            #!Proceso de descifrado
            with open('MensajeRecibido.txt', 'w') as salida:
                salida.write(decriptado)
                text.insert(INSERT,'\nMensaje descifrado y guardado en MensajeRecibido.txt\n')
    elif var.get()==0:
        text.insert(INSERT, 'No ha seleccionado metodo de encriptacion\n')
    else:
        text.insert(INSERT, 'No ha seleccionado archivo\n')
# -------------------------------------------------------------------------- #
#                        Orden de la ventana (interfaz)                      #
# -------------------------------------------------------------------------- #
if __name__ == '__main__':
    root = tk.Tk()
    root.geometry("1080x720")
    root.resizable(False, False)
    root.title("Seguridad Informatica - Laboratorio 4")

    #!Fondo de pantalla
    bg = tk.PhotoImage(file = "fondo.png")
    label1 = tk.Label(root, image = bg)
    label1.place(x = -2, y = 0)
    
    #!Botones para opciones
    #orden = tk.Frame(width=600, height=400).pack(padx=20, pady=100)
    var = tk.IntVar()
    opcion1 = tk.Radiobutton(root, text="ElGamal", variable=var, value=1)
    opcion1.place(relx = 0.5, rely = 0.25, anchor = "center")
    opcion2 = tk.Radiobutton(root, text="RSA", variable=var, value=2)
    opcion2.place(relx = 0.5, rely = 0.30, anchor = "center")
    text = tk.Text(root, height = 10, width = 45)
    text.place(relx = 0.5, rely = 0.45, anchor = "center")
    
    #!Botones de accion
    b1 = tk.Button(root, text='Realizar Proceso Cifrado', command=encrypt)
    b1.place(relx = 0.5, rely = 0.6, anchor = "center")
    b2 = tk.Button(root, text='Salir', command=root.quit)
    b2.place(relx = 0.5, rely = 0.65, anchor = "center")

    root.mainloop()
