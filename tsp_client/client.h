#ifndef CLIENT_H
#define CLIENT_H

#include <QTcpSocket>
#include <QTcpServer>
#include <QObject>
#include <fstream>
#include <string>

#include "request.h"

class client : public QObject
{
    Q_OBJECT

public:
    explicit client(const QString& tsa, int nPort,
           tsp::Request* req, QString outFile);

private:
    QByteArray data;
    QTcpServer* mTcpServer;
    QTcpSocket* mTcpSocket;
    int i = 0;
    void print_to_file(std::ofstream& out, QString answer);
};

#endif // CLIENT_H
