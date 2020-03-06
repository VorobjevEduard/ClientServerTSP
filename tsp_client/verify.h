#ifndef VERIFY_H
#define VERIFY_H

#include <iostream>
#include <string>
#include <windows.h>
#include <wincrypt.h>
#include <stdlib.h>
#include <wtypes.h>
#include <wincrypt.h>

// подключение библиотеки crypt32.lib
#pragma comment (lib, "Crypt32")

// функция обратного вызова для структуры
// CRYPT_VERIFY_MESSAGE_PARA VerifyParams
PCCERT_CONTEXT WINAPI MyGetSignerCertificateCallback(
  void *pvGetArg,                  // in
  DWORD dwCertEncodingType,        // in
  PCERT_INFO pSignerId,            // in
  HCERTSTORE hMsgCertStore         // in
);

// перевод hex-подписи в бинарное представление
int hex2bin(const char* hexsign, BYTE* pbarray);

// вывод информации об ошибоках с помощью GetLastError()
void HandleError(std::string s);

// инициализация и начало работы
int init(const char* s, const char* hs);

// статус подписи
extern bool status;

#endif // VERIFY_H
