from utils import GeneratorBBS
from utils import Hash

# Пароль -> Hash -> Затравка -> Генератор ГПСЧ -> Гамма -> Шифр <- Входной текст

class StreamCipher:

    seed: str = 'secret'
    
    def __init__(self):
        self.hasher = Hash()
        self.prng = GeneratorBBS()

    def encrypt(self, text: str|bytes, password: str) -> str:
        if len(password) > 64 or len(password) <= 2:
            raise Exception("Длина текста должна быть больше 2 байт и меньше 64 байт")
        if len(text) > 6144 or len(text) < 4 :
           raise Exception("Длина текста должна быть больше 4 байт и меньше 6144 байт")
        if len(text) < len(password):
            raise Exception("Размер пароля должна быть меньше размера данных")

        pswhash: int = self.__hashpassword(self.seed, password) # генерируем хеш из пароля и затравки
        textlength: int = len(text) # размер файла в кол-ве байтов

        rndsequence: list[int] = self.prng.generate(pswhash, (textlength * 8))
        rndsequence: int = self.__digestrandomsequence(rndsequence) # представляем ее числом
        text: int = self.__digesttext(text)
        gamma: int = self.__gamming(pswhash, rndsequence) # гаммируем хеш-пароль и ПСЧ (0100101001...)

        return format(text ^ gamma, 'X')
    
    def decrypt(self, cipher: str, password: str, datatype: str='text'):
        cipher: int = int(cipher, 16)
        datalength: int = len(bin(cipher)[1:]) // 8
        pswhash: int = self.__hashpassword(self.seed, password) # генерируем хеш из пароля и затравки
        rndsequence: list[int] = self.prng.generate(pswhash, (datalength * 8))
        rndsequence: int = self.__digestrandomsequence(rndsequence)
        gamma: int = self.__gamming(pswhash, rndsequence)
        intdata: int = cipher ^ gamma
        bytesdata: bytes = int.to_bytes(intdata, length=datalength, byteorder='big', signed=False)
        if datatype.lower() == 'text':
            return bytesdata.decode('UTF-8')
        else:
            return bytesdata

    def __hashpassword(self, seed: str, password: str) -> str:
        return self.hasher.mahash5(password + seed)
        
    def __digesttext(self, text: str|bytes) -> int:
        if isinstance(text, str):
            text: bytes = text.encode('UTF-8')
        digesttext: int = int.from_bytes(text, byteorder='big', signed=False)
        return digesttext
    
    def __digestrandomsequence(self, sequence: list[int]) -> str:
        return int("".join([str(el) for el in sequence]), 2)
    
    def __gamming(self, pswhash: int, rndsequence: int) -> int:
        return pswhash | rndsequence 
        

# scipher = StreamCipher()

# with open('E:\Study\IV Курс\Информационная Безопасность\Лабораторная работа №3\data\paint.png', 'rb') as file:
#     text = file.read()

# with open('E:\Study\IV Курс\Информационная Безопасность\Лабораторная работа №3\data\password.txt', 'r', encoding='UTF-8') as file:
#     psw = file.read()

# res = scipher.encrypt(text=text, password='password')
# unres = scipher.decrypt(cipher=res, password='password', datatype='image')

# with open('E:\Study\IV Курс\Информационная Безопасность\Лабораторная работа №3\data\paint1.png', 'wb') as file:
#     file.write(unres)

# print("[INFO] Результат шифрования: ", res)
# print("[INFO] Результат дешифрования: ", unres)