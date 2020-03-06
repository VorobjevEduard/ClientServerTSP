#include <iostream>
#include <string>
#include <QDate>
#include <QTime>

#include "server.h"
#include "crypto.h"

server::server(int nPort, QObject* parent) : QObject(parent)
{
    mTcpServer = new QTcpServer(this);

    connect(mTcpServer, &QTcpServer::newConnection,
            this, &server::slotNewConnection
           );

    if (!mTcpServer->listen(QHostAddress::LocalHost, nPort)) {
        std::cout << "Server Error, unable to start the server: "
                  << mTcpServer->errorString().toStdString() << std::endl;
        mTcpServer->close();
        return;
    } else {
        std::cout << "Server started" << std::endl;
    }
}

void server::slotNewConnection()
{
    mTcpSocket = mTcpServer->nextPendingConnection();
    mTcpSocket->write("Connection established");
    mTcpSocket->flush();
    mTcpSocket->waitForBytesWritten(3000);
    connect(mTcpSocket, &QTcpSocket::readyRead, this, &server::slotServerRead);
}

void server::slotServerRead()
{
    if (mTcpSocket->waitForConnected(3000))
    {
        mTcpSocket->waitForReadyRead(3000);
        QByteArray rawDataFromClient = mTcpSocket->readAll();
        QStringList dataFromClient = QString(rawDataFromClient).split(" ");
        QString version = dataFromClient[0];
        QString hash_alg = dataFromClient[1];
        QString hashed_msg = dataFromClient[2];
        QString policy = dataFromClient[3];
        QString nonce = dataFromClient[4];
        QString cert_req = dataFromClient[5];
        QString extensions = dataFromClient[6];

        QDate currentDate = QDate::currentDate();
        QString strCurrentDateTime = QString::number(currentDate.year()) +
                                     QString::number(currentDate.month()) +
                                     QString::number(currentDate.day());

        QTime currentTime = QTime::currentTime();
        strCurrentDateTime += QString::number(currentTime.hour()) +
                              QString::number(currentTime.minute()) +
                              QString::number(currentTime.second()) + "Z";

        tsp::Request request = tsp::Request(
                    version, hash_alg, hashed_msg, policy, nonce, cert_req, extensions);

        tsp::Response tempResponse = tsp::Response(version, policy, hash_alg, hashed_msg, "1",
                     strCurrentDateTime, 0, 0, 0, "ordering", nonce, "mytsa", extensions);

        status.PKIStatus = tsp::Status::granted;
        status.PKIFreeText = "pki_free_text";

        bool is_request_correct = true;

        // проверка того, что алгоритм хеширования поддерживается
        if ((request.get_hash_algorithm().compare("sha1") != 0) &&
                (request.get_hash_algorithm().compare("sha256") != 0))
        {
            std::cout << "Unrecognized or unsupported algorithm identifier" << std::endl;
            status.PKIStatus = tsp::Status::rejection;
            status.PKIFailureInfo = tsp::Status::BadAlg;
            is_request_correct = false;
        }

        // проверка того, что длина хеша соответствует алгоритму хеширования
        if ((request.get_hash_algorithm().compare("sha1") == 0 &&
                request.get_hashed_message().length() != 40) ||
                (request.get_hash_algorithm().compare("sha256") == 0 &&
                 request.get_hashed_message().length() != 64))
        {
            std::cout << "The data submitted has the wrong format" << std::endl;
            status.PKIStatus = tsp::Status::rejection;
            status.PKIFailureInfo = tsp::Status::BadDataFormat;
            is_request_correct = false;
        }

        if (is_request_correct) {
            std::cout << "Request is correct" << std::endl;
        }

        response = tempResponse;
        send_response();
    }
}

void server::send_response()
{
    // ответ сервера клиенту
    QString data = "";

    // подпись ответа
    QString sign = "";

    if (status.PKIStatus == tsp::Status::granted)
        data += "granted ";
    else if (status.PKIStatus == tsp::Status::grantedWithMods)
        data += "grantedWithMods ";
    else if (status.PKIStatus == tsp::Status::rejection)
        data += "rejection ";
    else if (status.PKIStatus == tsp::Status::waiting)
        data += "waiting ";
    else if (status.PKIStatus == tsp::Status::revocationWarning)
        data += "revocationWarning ";
    else if (status.PKIStatus == tsp::Status::revocationNotification)
        data += "revocationNotification ";

    data += status.PKIFreeText + " ";

    if (status.PKIFailureInfo == tsp::Status::BadAlg)
        data += "BadAlg ";
    else if(status.PKIFailureInfo == tsp::Status::BadRequest)
        data += "BadRequest ";
    else if(status.PKIFailureInfo == tsp::Status::BadDataFormat)
        data += "BadDataFormat ";
    else if(status.PKIFailureInfo == tsp::Status::TimeNotAvailable)
        data += "TimeNotAvailable ";
    else if(status.PKIFailureInfo == tsp::Status::UnacceptedPolicy)
        data += "UnacceptedPolicy ";
    else if(status.PKIFailureInfo == tsp::Status::UnacceptedExtension)
        data += "UnacceptedExtension ";
    else if(status.PKIFailureInfo == tsp::Status::AddInfoNotAvailable)
        data += "AddInfoNotAvailable ";
    else if(status.PKIFailureInfo == tsp::Status::SystemFailure)
        data += "SystemFailure ";
    else if(status.PKIFailureInfo == tsp::Status::Unknown)
        data += "Unknown ";
    else
        data += " ";

    if (status.PKIStatus == tsp::Status::granted ||
            status.PKIStatus == tsp::Status::grantedWithMods)
    {
        data += response.get_version() + " " +
                response.get_policy() + " " +
                response.get_hash_algorithm() + " " +
                response.get_hashed_message() + " " +
                response.get_serial_number() + " " +
                response.get_gen_time() + " " +
                QString::number(response.get_seconds()) + " " +
                QString::number(response.get_millis()) +  " " +
                QString::number(response.get_micros()) +  " " +
                response.get_ordering() +  " " +
                response.get_nonce() +  " " +
                response.get_tsa() +  " " +
                response.get_extensions();
    } // на данном этапе ответ полностью сформирован

    // подпись сформированного ответа
    sign = init_c(data.toStdString().c_str());

    // отправка подписи и сообщения
    QByteArray response = (sign + "|" + data).toLocal8Bit();
    mTcpSocket->write(response);
    //mTcpSocket->flush();
    mTcpSocket->waitForBytesWritten(3000);
    std::cout << "Response sent" << std::endl;
}
