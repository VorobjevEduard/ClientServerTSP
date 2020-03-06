#ifndef REQUEST_H
#define REQUEST_H

#include <QString>

namespace tsp
{

class Request
{
public:
    Request();

    Request(QString v, QString hash_alg, QString hashed_msg,QString req_policy = "",
            QString nonce = "", QString cert_req = "", QString extensions = "");

    Request(const Request& t);

    ~Request();

    Request& operator=(const Request& t);

    QString get_version() const;

    QString get_hash_algorithm() const;

    QString get_hashed_message() const;

    QString get_req_policy() const;

    QString get_nonce() const;

    QString get_cert_req() const;

    QString get_extensions() const;

private:
    struct message_imprint
    {
        QString hash_algorithm;
        QString hashed_message;
    };

    struct time_stamp_request
    {
        QString version;
        message_imprint msg_imprint;
    };

    time_stamp_request* tsr;
    QString req_policy;
    QString nonce;
    QString cert_req;
    QString extensions;
};

}

#endif // REQUEST_H
