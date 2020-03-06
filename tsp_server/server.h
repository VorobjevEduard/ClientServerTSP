#ifndef SERVER_H
#define SERVER_H

#include <QTcpServer>
#include <QTcpSocket>
#include <QObject>

#include "request.h"
#include "status.h"
#include "response.h"

class server: public QObject
{
    Q_OBJECT
public:
    explicit server(int nPort, QObject* parent = nullptr);

    tsp::Request request;
    tsp::Status status;
    tsp::Response response;

public slots:
    void slotNewConnection();
    void slotServerRead();

private:
    void send_response();

    QTcpServer * mTcpServer;
    QTcpSocket * mTcpSocket;
};

#endif // SERVER_H
