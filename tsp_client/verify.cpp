#include "verify.h"

// по умолчанию подпись неверна
bool status = false;

// тип формата подписи и тип протокола
#define MY_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

// название персонального хранилища
#define CERT_STORE_NAME  L"MY"

// название сертификата, установленного в это хранилище
#define SIGNER_NAME  L"Eduard"

// функция обратного вызова для структуры
// CRYPT_VERIFY_MESSAGE_PARA VerifyParams
PCCERT_CONTEXT WINAPI MyGetSignerCertificateCallback(
  void *pvGetArg,                  // in
  DWORD dwCertEncodingType,        // in
  PCERT_INFO pSignerId,            // in
  HCERTSTORE hMsgCertStore         // in
)
{
  return PCCERT_CONTEXT(pvGetArg);
};

int init(const char* s, const char* hs)
{
    // сообщение
    BYTE* pbMessage = (BYTE*) s;
    DWORD cbMessage = (DWORD)strlen((char*) pbMessage)+1;

    // цифровая подпись к сообщению в формате PKSC#7
    const char* hexsign = hs;

    // переменные для указателя и длины подписи в текстовом виде
    DWORD cbArray = (DWORD)strlen(hexsign)/2 ;
    BYTE* pbArray = new BYTE[cbArray];

    // перевод цифровой подписи в бинарное представление
    if (hex2bin(hexsign, pbArray))
    {
        std::cout << "Error hex2bin" << std::endl;
        exit(1);
    }

    // открытие хранилища сертификатов
    HCERTSTORE hStoreHandle;

    if ( !( hStoreHandle = CertOpenStore(
        CERT_STORE_PROV_SYSTEM,
        0,
        NULL,
        CERT_SYSTEM_STORE_CURRENT_USER,
        //CERT_SYSTEM_STORE_LOCAL_MACHINE,
        CERT_STORE_NAME)))
    {
        HandleError("cannot open storage");
    }

    // получаем указатель на наш сертификат
    PCCERT_CONTEXT pSignerCert;

    if(pSignerCert = CertFindCertificateInStore(
        hStoreHandle,
        MY_TYPE,
        0,
        CERT_FIND_SUBJECT_STR,
        SIGNER_NAME,
        NULL))
    {
        std::cout << "Certificate found" << std::endl;
    }
    else
    {
        HandleError("certificate not found");
    }

    CRYPT_VERIFY_MESSAGE_PARA VerifyParams;

    // заполнение структуры для верификации

    VerifyParams.cbSize = sizeof(CRYPT_VERIFY_MESSAGE_PARA);
    VerifyParams.dwMsgAndCertEncodingType = MY_TYPE;
    VerifyParams.hCryptProv = 0;
    VerifyParams.pfnGetSignerCertificate = MyGetSignerCertificateCallback;
    VerifyParams.pvGetArg = (void*)pSignerCert;

    const BYTE* MessageArray[] = {pbMessage};
    DWORD MessageSizeArray[1];
    MessageSizeArray[0] = cbMessage;

    // верификация подписи
    if(CryptVerifyDetachedMessageSignature(
        &VerifyParams,          // указатель на структуру VerifyParams
        0,                      //
        pbArray,    // указатель на подпись
        cbArray,    // длина подписи
        1,                      // число сообщений
        MessageArray,           // сообщение
        MessageSizeArray,       // длина сообщения
        &pSignerCert))      // указатель на сертификат
    {
        std::cout << "Verification was successful" << std::endl;
        status = true;
    }
    else
    {
        HandleError("verification was failure");
    }

    // освобождаем память

    if(pbArray)
        delete pbArray;

    if(pSignerCert)
        CertFreeCertificateContext(pSignerCert);

    if(CertCloseStore(hStoreHandle, CERT_CLOSE_STORE_CHECK_FLAG))
    {
        std::cout << "Storage closed" << std::endl;
    }
    else
    {
        std::cout << "Error closing storage" << std::endl;
    }

    return 0;
}

void HandleError(std::string s)
{
    std::cout << "Error N" << std::hex << GetLastError() << " : ";
    std::cout << s << std::endl;
    exit(1);
}

int hex2int(char ch) throw(...)
{
  if (ch >= '0' && ch <= '9') return ch - '0';
  if (ch >= 'a' && ch <= 'f') return ch - 'a' + 0xA;
  if (ch >= 'A' && ch <= 'F') return ch - 'A' + 0xA;
  throw 1;
}

int hex2bin(const char* hexsign, BYTE* pbarray)
{
  try{
    while(*hexsign)
    {
      int aa = hex2int(*hexsign++);
      int bb = hex2int(*hexsign++);
      *pbarray++ = (BYTE)(aa << 4 | bb);
    }
  }
  catch(...) {
    return -1;
  }
  return 0;
}
