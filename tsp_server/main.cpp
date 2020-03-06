#include <QCoreApplication>

#include "request.h"
#include "server.h"
#include "crypto.h"

int main(int argc, char** argv)
{
    QCoreApplication a(argc, argv);

    server* tsa = new server(55555);

    return a.exec();
}


