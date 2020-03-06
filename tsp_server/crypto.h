#ifndef CRYPTO_H
#define CRYPTO_H

#include <iostream>
#include <string>
#include <windows.h>
#include <wincrypt.h>
#include <stdlib.h>
#include <stdio.h>
#include <wtypes.h>
#include <wincrypt.h>
#include <QString>

// подключение библиотеки crypt32.lib
#pragma comment (lib, "Crypt32")

// печать подписанного сообщения на экране
void print_signature(DWORD cbSigned, BYTE* pbSigned);

// вывод информации об ошибоках с помощью GetLastError()
void HandleError(std::string s);

// инициализация и начало работы
QString init_c(const char*);

#endif // CRYPTO_H
