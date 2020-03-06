#include "crypto.h"

// тип формата подписи и тип протокола
#define MY_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

// наименование персонального хранилища
#define CERT_STORE_NAME  L"MY"

// наименование сертификата установленного в это хранилище
#define SIGNER_NAME  L"Eduard"

QString init_c(const char* s)
{
    BYTE* pbMessage = (BYTE*) s;
    DWORD cbMessage = (DWORD)strlen((char*)pbMessage) + 1;

    QString result = "";

    // открываем хранилище сертификатов
    HCERTSTORE hStoreHandle;

    if (!(hStoreHandle = CertOpenStore(
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

    if (pSignerCert = CertFindCertificateInStore(
        hStoreHandle,
        MY_TYPE,
        0,
        CERT_FIND_SUBJECT_STR,
        SIGNER_NAME,
        NULL))
    {
        std::cout << "Certificate found" << std::endl;;
    }
    else
    {
        HandleError("certificate not found");
    }


    // переменные для указателя и длины подписи
    BYTE  *pbSignedMessageBlob;
    DWORD cbSignedMessageBlob;

    // создаем и заполняем структуру для создания ц.п.
    CRYPT_SIGN_MESSAGE_PARA  SigParams;

    SigParams.cbSize = sizeof(CRYPT_SIGN_MESSAGE_PARA);
    SigParams.dwMsgEncodingType = MY_TYPE;
    SigParams.pSigningCert = pSignerCert;
    SigParams.HashAlgorithm.pszObjId = const_cast<LPSTR>("1.2.840.113549.2.5");
    SigParams.HashAlgorithm.Parameters.cbData = NULL;
    SigParams.cMsgCert = 0;
    SigParams.rgpMsgCert = NULL;
    SigParams.cAuthAttr = 0;
    SigParams.dwInnerContentType = 0;
    SigParams.cMsgCrl = 0;
    SigParams.cUnauthAttr = 0;
    SigParams.dwFlags = 0;
    SigParams.pvHashAuxInfo = NULL;
    SigParams.rgAuthAttr = NULL;


    const BYTE* MessageArray[] = { pbMessage };
    DWORD MessageSizeArray[1];
    MessageSizeArray[0] = cbMessage;

    // получаем длину буфера подписи
    if (CryptSignMessage(
        &SigParams,         	// указатель на SigParams
        TRUE,                  	// подпись создается отдельно
        1,	                 	// число сообщений
        MessageArray,          	// сообщение
        MessageSizeArray,   	// длина сообщения
        NULL,                  	// буфер для подписи
        &cbSignedMessageBlob)) 	// размер буфера
    {
        std::cout << "Size of signature " << cbSignedMessageBlob << std::endl;
    }
    else
    {
        HandleError("Error CryptSignMessage.");
    }

    // выделяем память под подпись
    if (!(pbSignedMessageBlob = new BYTE[cbSignedMessageBlob]))
    {
        HandleError("Error");
    }

    // формируем подпись
    if (CryptSignMessage(
        &SigParams,            // указатель на SigParams
        TRUE,                  // подпись создается отдельно
        1,                     // число сообщений
        MessageArray,          // сообщение
        MessageSizeArray,      // длина сообщения
        pbSignedMessageBlob,   // буфер для подписи
        &cbSignedMessageBlob)) // размер буфера
    {
        std::cout <<"Signature:" << std::endl;
        print_signature(cbSignedMessageBlob, pbSignedMessageBlob);
        for (DWORD i = 0; i < cbSignedMessageBlob; i++)
        {
            char temp[] = "    ";
            sprintf(temp, "%2.2x", pbSignedMessageBlob[i]);
            result += QString(temp);
        }
    }
    else
    {
        HandleError("Error");
    }

    if (pbSignedMessageBlob)
        delete pbSignedMessageBlob;

    if (pSignerCert)
        CertFreeCertificateContext(pSignerCert);

    if (CertCloseStore(hStoreHandle, CERT_CLOSE_STORE_CHECK_FLAG))
    {
        std::cout << std::endl << "Storage closed" << std::endl;
    }
    else
    {
        std::cout << "Error!" << std::endl;
    }

    return result;
}

void print_signature(DWORD cbSigned, BYTE* pbSigned)
{
    for (DWORD i = 0; i < cbSigned; i++)
    {
        printf("%2.2x", pbSigned[i]);
        if ((i + 1) % 32 == 0) printf("\n");
    }
}

void HandleError(std::string s)
{
    std::cout << "Error N" << std::hex << GetLastError() << " : ";
    std::cout << s << std::endl;
    exit(1);
}
