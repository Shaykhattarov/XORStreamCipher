from utils import GeneratorBBS
from utils import Hash

# Пароль -> Hash -> Затравка -> Генератор ГПСЧ -> Гамма -> Шифр <- Входной текст

ENCODING = "UTF-8"

class StreamCipher:

    seed: str = 'secret'
    
    def __init__(self):
        self.hasher = Hash()
        self.prng = GeneratorBBS()

    def encrypt(self, text: str|bytes, password: str) -> str:
        if len(password) < 2 or len(text) < 2:
            raise Exception("Длина текста и пароля должна быть больше 2 байт")
        textbytes: bytearray = self.__converttexttobytearray(text)
        gamma: bytearray = self.__generate_gamma(password, len(textbytes))
        cipher: bytearray = self.__xor(textbytes, gamma)
        return cipher.hex() # преобразуем к виду в 16-ричном формате
    
    def decrypt(self, cipher: str, password: str, datatype: str='text') -> str|bytearray:
        cipher: bytes = bytes.fromhex(cipher)
        gamma: bytearray = self.__generate_gamma(password, len(cipher))
        decrypted: bytearray = self.__xor(cipher, gamma)
        
        if datatype.lower() == 'text':
            return decrypted.decode('UTF-8')
        return decrypted
        
    def __generate_gamma(self, password: str, datalength: int) -> bytearray:
        pswhash: int = self.__hashpassword(self.seed, password) # генерируем хеш из пароля и затравки
        rndsequence: bytearray = self.__convertsequencetobytearray(self.prng.generate(pswhash, (datalength * 8))) # генерируем последовательность с помощью хеша пароля и преобразуем ее в bytearray длиной datalength
        pswhash: bytes = int.to_bytes(pswhash, length=len(rndsequence), byteorder='big', signed=False) # преобразование хеша пароля в bytes длиной datalength байт
        return [(pswhash[ind] | rndsequence[ind]) for ind in range(datalength)] # производим побитовое сложение байтов и возвращаем результат 

    def __converttexttobytearray(self, data: str|bytes) -> bytearray:
        if isinstance(data, str): return bytearray(data.encode(ENCODING))
        if isinstance(data, bytes): return bytearray(data)
    
    def __convertsequencetobytearray(self, sequence: list[int]) -> bytearray:
        buffer = ""
        result = bytearray()
        for i in range(len(sequence)):
            buffer += str(sequence[i])
            if len(buffer) % 8 == 0:
                result.append(int(buffer, 2))
                buffer = ""
        return result

    def __hashpassword(self, seed: str, password: str) -> str:
        return self.hasher.mahash5(password + seed)
        
    def __xor(self, text: bytearray, gamma: bytearray) -> bytearray:
        if len(text) != len(gamma):
            raise Exception("Длина ПСЧ и длина текста должны быть одинаковыми")
        result = bytearray()
        for i in range(len(text)):
            result.append(text[i] ^ gamma[i])
        return result
        

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