from Crypto import Random
from Crypto.PublicKey import RSA

def crearLlave():
    random_gen = Random.new().read
    rsa = RSA.generate(1024)
    private_pem = rsa.exportKey()
    public_pem = rsa.publickey().exportKey()
    with open('public.pem','wb') as f:
        f.write(public_pem)
        f.close()
    with open('private.pem','wb') as f:
        f.write(private_pem)
        f.close()
    
crearLlave()